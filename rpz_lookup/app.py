# -*- coding: utf-8 -*-

import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from os import environ
from typing import Any, Dict, List, Optional

import yaml
from flask import Flask, Response, abort, current_app, make_response, redirect, render_template, request, url_for
from flask_limiter import Limiter
from pymisp import PyMISPError
from validators import domain
from whitenoise import WhiteNoise

from rpz_lookup.misp_api import MISPApi
from rpz_lookup.utils import SightingsData, User, Votes, get_ipaddr_or_eppn, get_user

# Read config
config_path = environ.get('RPZ_LOOKUP_CONFIG', 'config.yaml')
try:
    with open(config_path) as f:
        config = yaml.safe_load(f)
except FileNotFoundError as e:
    print('Set environment variable RPZ_LOOKUP_CONFIG to config file path')
    print(e)
    sys.exit(1)

# Init app
app = Flask(__name__)
app.config.from_mapping(config)
# Init logging
app.config.setdefault('LOG_LEVEL', 'INFO')
app.logger.setLevel(app.config['LOG_LEVEL'])
# Init static files
app.wsgi_app = WhiteNoise(app.wsgi_app, root=config.get('STATIC_FILES', 'rpz_lookup/static/'))
# Init trusted user list
app.trusted_users = []
if app.config.get('TRUSTED_USERS'):
    try:
        with open(app.config['TRUSTED_USERS']) as f:
            app.trusted_users = yaml.safe_load(f)['eppn']
        app.logger.info('Loaded trusted user list')
        app.logger.debug(f'Trusted user list: {app.trusted_users}')
    except IOError as e:
        app.logger.warning(f'Could not initialize trusted user list: {e}')

# Init trusted orgs
app.trusted_orgs = {}
if app.config.get('TRUSTED_ORGS'):
    try:
        with open(app.config['TRUSTED_ORGS']) as f:
            app.trusted_orgs = yaml.safe_load(f)
        app.logger.info('Loaded trusted org list')
        app.logger.debug(f'Trusted org config: {app.trusted_orgs}')
    except IOError as e:
        app.logger.warning(f'Could not initialize trusted org mapping: {e}')

    # Make all orgs lower case
    org_domains = {}
    for key, value in app.trusted_orgs['org_domains'].items():
        org_domains[key.lower()] = value
    app.trusted_orgs['org_domains'] = org_domains

# Init other settings
app.config.setdefault('SIGHTING_SOURCE_PREFIX', 'flask-rpz-lookup_')
app.config.setdefault('SIGHTING_MIN_POSITIVE_VOTE_HOURS', 24)


# Init MISP APIs
misp_apis = {'default': MISPApi(app.config['MISP_URL'], app.config['MISP_KEY'], app.config['MISP_VERIFYCERT'])}


@contextmanager
def misp_api_for(user: Optional[User] = None) -> MISPApi:
    if user is None:
        # Use default api key as org specific api keys return org specific data
        user = User(identifier='default', is_trusted_user=False, in_trusted_org=False, org_domain='default')
        app.logger.debug('Default user used for api call')
    app.logger.debug(f'User {user.identifier} mapped to domain {user.org_domain}')

    # Lazy load apis per org
    if user.org_domain not in misp_apis and user.org_domain in app.trusted_orgs['org_domains']:
        try:
            misp_apis[user.org_domain] = MISPApi(
                app.config['MISP_URL'],
                app.trusted_orgs['org_domains'][user.org_domain],
                app.config['MISP_VERIFYCERT'],
            )
            app.logger.info(f'Loaded api for {user.org_domain}')
        except PyMISPError:
            abort(400, 'Authentication failed. Make sure your organizations api key is up to date.')
        except Exception as ex:
            app.logger.exception(f'Could not load domain mapping for {user.org_domain}: {ex}')

    api = misp_apis.get(user.org_domain)
    if api is None:
        app.logger.debug('Using default api')
        yield misp_apis['default']
    else:
        app.logger.debug(f'Using {user.org_domain} api')
        yield api


# Init rate limiting
limiter = Limiter(app, key_func=get_ipaddr_or_eppn)


def rate_limit_from_config():
    return app.config.get('REQUEST_RATE_LIMIT', '1/second')


@app.template_filter('ts')
def _jinja2_filter_ts(ts: str):
    dt = datetime.utcfromtimestamp(int(ts))
    fmt = '%Y-%m-%d %H:%M:%S'
    return dt.strftime(fmt)


def get_sightings_data(user: User, search_result: List[Dict[str, Any]]):
    attribute_votes = {}
    org_sightings = []
    with misp_api_for() as api:
        for item in search_result:
            votes = Votes()
            for sighting in api.domain_sighting_lookup(attribute_id=item['id']):
                if sighting['type'] == '0':
                    votes.positives += 1
                elif sighting['type'] == '1':
                    votes.negatives += 1
            attribute_votes[item['id']] = votes
            with misp_api_for(user) as org_api:
                org_sightings.extend(
                    org_api.domain_sighting_lookup(
                        attribute_id=item['id'],
                        source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
                    )
                )
    return SightingsData.from_sightings(data=org_sightings, votes=attribute_votes)


# Views
@app.route('/', defaults={'domain_name': None}, methods=['GET', 'POST'])
@app.route('/<domain_name>', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def index(domain_name=None):
    user = get_user()
    error = None
    if request.method == 'POST' or domain_name is not None:
        original_domain_name = request.form.get('domain_name')
        parent_domain_name = None
        if not original_domain_name:
            original_domain_name = domain_name

        if original_domain_name and domain(original_domain_name):
            with misp_api_for() as api:  # Use the default api to get non org specific data
                result = api.domain_name_lookup(original_domain_name)

            if not result:
                # Try searching for a less exact domain name
                parent_domain_name = '.'.join(original_domain_name.split('.')[1:])
                if parent_domain_name and domain(parent_domain_name):
                    with misp_api_for() as api:  # Use the default api to get non org specific data
                        result = api.domain_name_lookup(parent_domain_name)

            sightings_data = get_sightings_data(user=user, search_result=result)
            return render_template(
                'index.jinja2',
                result=result,
                original_domain_name=original_domain_name,
                parent_domain_name=parent_domain_name,
                misp_url=current_app.config['MISP_URL'],
                sightings_data=sightings_data,
                user=user,
            )

        error = f'Invalid domain name: "{original_domain_name}"'

    return render_template('index.jinja2', error=error, user=user)


@app.route('/report', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def report():
    user = get_user()
    if request.method == 'POST':
        domain_names_in = request.form.get('domain_names', '').split('\n')
        reference_in = ' '.join(request.form.get('reference', '').split())  # Normalise whitespace
        domain_names = []
        for domain_name in domain_names_in:
            if domain_name:
                domain_name = ''.join(domain_name.split())  # Normalize whitespace
                if not domain(domain_name):
                    return render_template('report.jinja2', error=f'Invalid domain name: "{domain_name}"', user=user)
                domain_names.append(domain_name)

        if not domain_names:
            error = f'No valid domain name found'
            return render_template('report.jinja2', error=error, user=user)

        tags = ['OSINT', 'TLP:GREEN']
        publish = False
        if user.is_trusted_user:
            publish = True

        with misp_api_for(user) as api:
            ret = api.add_event(
                domain_names=domain_names,
                info='From flask_rpz_lookup',
                tags=tags,
                comment=f'Reported by {user.identifier}',
                to_ids=True,
                reference=reference_in,
                published=publish,
            )
        current_app.logger.debug(ret)
        result = 'success'
        return render_template('report.jinja2', result=result, domain_names=domain_names, user=user)
    return render_template('report.jinja2', user=user)


@app.route('/report-sighting', methods=['POST'])
@limiter.limit(rate_limit_from_config)
def report_sighting():
    user = get_user()

    domain_name_in = request.form.get('domain_name', '')
    type_in = request.form.get('type', '')
    if not domain(domain_name_in) or not type_in:
        abort(400)

    if user.in_trusted_org:
        with misp_api_for() as api:
            result = api.domain_name_lookup(domain_name_in)
        sightings_data = get_sightings_data(user=user, search_result=result)

        if (sightings_data.can_add_sighting and type_in == '0') or (
            sightings_data.can_add_false_positive and type_in == '1'
        ):
            app.logger.debug(f'report-sighting: domain_name {domain_name_in}')
            app.logger.debug(f'report-sighting: type {type_in}')
            with misp_api_for(user) as api:
                api.add_sighting(
                    domain_name=domain_name_in,
                    sighting_type=type_in,
                    source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
                )
            return redirect(url_for('index', domain_name=domain_name_in))
    return abort(401)


@app.route('/remove-sighting', methods=['POST'])
@limiter.limit(rate_limit_from_config)
def remove_sighting():
    user = get_user()

    domain_name_in = request.form.get('domain_name', '')
    type_in = request.form.get('type', '')
    if not domain(domain_name_in) or not type_in:
        abort(400)

    if user.in_trusted_org:
        domain_name_in = request.form.get('domain_name', '')
        type_in = request.form.get('type', '')
        date_from = None
        date_to = None

        if type_in == '0':
            # Only remove sightings added in the last X hours
            min_vote_hours = current_app.config['SIGHTING_MIN_POSITIVE_VOTE_HOURS']
            date_to = datetime.utcnow()
            date_from = date_to - timedelta(hours=min_vote_hours)

        app.logger.debug(f'remove-sighting: domain_name {domain_name_in}')
        app.logger.debug(f'remove-sighting: type {type_in}')
        app.logger.debug(f'remove-sighting: date_from {date_from}')
        app.logger.debug(f'remove-sighting: date_to {date_to}')

        with misp_api_for(user) as api:
            api.remove_sighting(
                domain_name=domain_name_in,
                sighting_type=type_in,
                date_from=date_from,
                date_to=date_to,
                source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
            )
        return redirect(url_for('index', domain_name=domain_name_in))
    return abort(401)


if __name__ == '__main__':
    app.run()
