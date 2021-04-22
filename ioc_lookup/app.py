# -*- coding: utf-8 -*-

import sys
import urllib.parse
from datetime import datetime, timedelta
from os import environ

import yaml
from flask import Flask, abort, current_app, redirect, render_template, request, url_for
from flask_limiter import Limiter
from validators import domain
from whitenoise import WhiteNoise

from ioc_lookup.misp_api import AttrType, MISPApi
from ioc_lookup.utils import (
    ParseException,
    get_ipaddr_or_eppn,
    get_sightings_data,
    get_user,
    misp_api_for,
    parse_item,
    parse_items,
)

# Read config
config_path = environ.get('IOC_LOOKUP_CONFIG', 'config.yaml')
try:
    with open(config_path) as f:
        config = yaml.safe_load(f)
except FileNotFoundError as e:
    print('Set environment variable IOC_LOOKUP_CONFIG to config file path')
    print(e)
    sys.exit(1)

# Init app
app = Flask(__name__)
app.config.from_mapping(config)
# Init logging
app.config.setdefault('LOG_LEVEL', 'INFO')
app.logger.setLevel(app.config['LOG_LEVEL'])
# Init static files
app.wsgi_app = WhiteNoise(app.wsgi_app, root=config.get('STATIC_FILES', 'ioc_lookup/static/'))
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
app.config.setdefault('SIGHTING_SOURCE_PREFIX', 'flask-ioc-lookup_')
app.config.setdefault('SIGHTING_MIN_POSITIVE_VOTE_HOURS', 24)


# Init MISP APIs
app.misp_apis = {'default': MISPApi(app.config['MISP_URL'], app.config['MISP_KEY'], app.config['MISP_VERIFYCERT'])}


# Init rate limiting
limiter = Limiter(app, key_func=get_ipaddr_or_eppn)


def rate_limit_from_config():
    return app.config.get('REQUEST_RATE_LIMIT', '1/second')


@app.template_filter('ts')
def _jinja2_filter_ts(ts: str):
    dt = datetime.utcfromtimestamp(int(ts))
    fmt = '%Y-%m-%d %H:%M:%S'
    return dt.strftime(fmt)


# Views
@app.route('/', defaults={'search_query': None}, methods=['GET', 'POST'])
@app.route('/<search_query>', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def index(search_query=None):
    user = get_user()
    error = None
    if request.method == 'POST' or search_query is not None:
        original_search_query = request.form.get('search_query')
        parent_domain_name = None
        if not original_search_query:
            original_search_query = search_query

        search_item = parse_item(original_search_query)
        if search_item:
            with misp_api_for() as api:  # Use the default api to get non org specific data
                result = api.attr_lookup(search_item)
                if not result and search_item.type is AttrType.DOMAIN:
                    # Try searching for a less exact domain name
                    parent_domain_name = '.'.join(search_item.name.split('.')[1:])
                    if parent_domain_name and domain(parent_domain_name):
                        result = api.domain_name_lookup(parent_domain_name)

            sightings_data = get_sightings_data(user=user, search_result=result)
            return render_template(
                'index.jinja2',
                result=result,
                original_search_query=search_item.name,
                parent_domain_name=parent_domain_name,
                misp_url=current_app.config['MISP_URL'],
                sightings_data=sightings_data,
                user=user,
            )

        error = f'Invalid domain name or url: "{original_search_query}"'

    return render_template('index.jinja2', error=error, user=user)


@app.route('/report', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def report():
    user = get_user()
    if request.method == 'POST':
        reference_in = ' '.join(request.form.get('reference', '').split())  # Normalise whitespace
        try:
            report_items = parse_items(request.form.get('report_query', ''))
        except ParseException as ex:
            app.logger.error(ex)
            return render_template('report.jinja2', error=f'Invalid domain name or URL', user=user)

        if not report_items:
            error = f'No valid domain name or URL name found'
            return render_template('report.jinja2', error=error, user=user)

        tags = ['OSINT', 'TLP:GREEN']
        publish = False
        if user.is_trusted_user:
            publish = True

        with misp_api_for(user) as api:
            if report_items:
                ret = api.add_event(
                    attr_items=report_items,
                    info='From flask_ioc_lookup',
                    tags=tags,
                    comment=f'Reported by {user.identifier}',
                    to_ids=True,
                    reference=reference_in,
                    published=publish,
                )
                current_app.logger.debug(f'domain_names ret: {ret}')

        result = 'success'
        return render_template('report.jinja2', result=result, reported_items=report_items, user=user)
    return render_template('report.jinja2', user=user)


@app.route('/report-sighting', methods=['POST'])
@limiter.limit(rate_limit_from_config)
def report_sighting():
    user = get_user()
    if not user.in_trusted_org:
        return abort(401)

    sighting_in = parse_item(request.form.get('search_query', ''))
    type_in = request.form.get('type', '')
    if not sighting_in or not type_in:
        abort(400)

    with misp_api_for() as api:
        result = api.attr_lookup(sighting_in)

    sightings_data = get_sightings_data(user=user, search_result=result)
    if (sightings_data.can_add_sighting and type_in == '0') or (
        sightings_data.can_add_false_positive and type_in == '1'
    ):
        app.logger.debug(f'report-sighting: {sighting_in.type.name} {sighting_in.name}')
        app.logger.debug(f'report-sighting: type {type_in}')
        with misp_api_for(user) as api:
            api.add_sighting(
                attr=sighting_in,
                sighting_type=type_in,
                source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
            )
        return redirect(url_for('index', search_query=urllib.parse.quote_plus(sighting_in.name)))


@app.route('/remove-sighting', methods=['POST'])
@limiter.limit(rate_limit_from_config)
def remove_sighting():
    user = get_user()
    if not user.in_trusted_org:
        return abort(401)

    sighting_in = parse_item(request.form.get('search_query', ''))
    type_in = request.form.get('type', '')
    if not sighting_in or not type_in:
        abort(400)

    date_from = None
    date_to = None

    if type_in == '0':
        # Only remove sightings added in the last X hours
        min_vote_hours = current_app.config['SIGHTING_MIN_POSITIVE_VOTE_HOURS']
        date_to = datetime.utcnow()
        date_from = date_to - timedelta(hours=min_vote_hours)

    app.logger.debug(f'remove-sighting: domain_name {sighting_in}')
    app.logger.debug(f'remove-sighting: type {type_in}')
    app.logger.debug(f'remove-sighting: date_from {date_from}')
    app.logger.debug(f'remove-sighting: date_to {date_to}')

    with misp_api_for(user) as api:
        api.remove_sighting(
            attr=sighting_in,
            sighting_type=type_in,
            date_from=date_from,
            date_to=date_to,
            source=f'{app.config["SIGHTING_SOURCE_PREFIX"]}{user.org_domain}',
        )

    return redirect(url_for('index', search_query=urllib.parse.quote_plus(sighting_in.name)))


if __name__ == '__main__':
    app.run()