# -*- coding: utf-8 -*-

import sys
from contextlib import contextmanager
from datetime import datetime
from os import environ

import yaml
from flask import Flask, current_app, render_template, request, abort, jsonify
from flask_limiter import Limiter
from pymisp import PyMISPError
from validators import domain
from whitenoise import WhiteNoise

from rpz_lookup.misp_api import MISPApi
from rpz_lookup.utils import get_ipaddr_or_eppn, is_trusted_user, get_org_domain

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


# Init MISP APIs
misp_apis = {'default': MISPApi(app.config['MISP_URL'], app.config['MISP_KEY'], app.config['MISP_VERIFYCERT'])}


@contextmanager
def misp_api_for(user: str) -> MISPApi:
    org_domain = get_org_domain(user)
    app.logger.debug(f'User {user} mapped to domain {org_domain}')

    # Lazy load apis per org
    if org_domain not in misp_apis and org_domain in app.trusted_orgs['org_domains']:
        try:
            misp_apis[org_domain] = MISPApi(
                app.config['MISP_URL'],
                app.trusted_orgs['org_domains'][org_domain],
                app.config['MISP_VERIFYCERT'],
            )
            app.logger.info(f'Loaded api for {org_domain}')
        except PyMISPError:
            abort(400, 'Authentication failed. Make sure your organizations api key is up to date.')
        except Exception as ex:
            app.logger.exception(f'Could not load domain mapping for {org_domain}: {ex}')

    api = misp_apis.get(org_domain)
    if api is None:
        app.logger.debug('Using default api')
        yield misp_apis['default']
    else:
        app.logger.debug(f'Using {org_domain} api')
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


# Views
@app.route('/', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def index():
    user = get_ipaddr_or_eppn()
    error = None
    if request.method == 'POST':
        original_domain_name = request.form.get('domain_name')
        parent_domain_name = None
        if original_domain_name and domain(original_domain_name):
            with misp_api_for('default') as api:
                result = api.domain_name_lookup(original_domain_name)
                for item in result:
                    item['positives'] = 0
                    item['negatives'] = 0
                    for sighting in api.domain_sighting_lookup(item['id']):
                        if sighting['type'] == '0':
                            item['positives'] += 1
                        elif sighting['type'] == '1':
                            item['negatives'] += 1

            if not result:
                # Try searching for a less exact domain name
                parent_domain_name = '.'.join(original_domain_name.split('.')[1:])
                if parent_domain_name and domain(parent_domain_name):
                    with misp_api_for('default') as api:
                        result = api.domain_name_lookup(parent_domain_name)
            return render_template(
                'index.jinja2',
                result=result,
                original_domain_name=original_domain_name,
                parent_domain_name=parent_domain_name,
                misp_url=current_app.config['MISP_URL'],
                user=user,
            )
        error = f'Invalid domain name: "{original_domain_name}"'

    return render_template('index.jinja2', error=error, user=user)


@app.route('/report', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def report():
    user = get_ipaddr_or_eppn()
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
        if is_trusted_user(user):
            publish = True

        with misp_api_for(user) as api:
            ret = api.add_event(
                domain_names=domain_names,
                info='From flask_rpz_lookup',
                tags=tags,
                comment=f'Reported by {user}',
                to_ids=True,
                reference=reference_in,
                published=publish,
            )
        current_app.logger.debug(ret)
        result = 'success'
        return render_template('report.jinja2', result=result, domain_names=domain_names, user=user)
    return render_template('report.jinja2', user=user)


if __name__ == '__main__':
    app.run()
