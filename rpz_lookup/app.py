# -*- coding: utf-8 -*-

import sys
from datetime import datetime
from os import environ

import yaml
from flask import Flask, current_app, render_template, request
from flask_limiter import Limiter
from validators import domain
from whitenoise import WhiteNoise

from rpz_lookup.misp_api import MISPApi
from rpz_lookup.utils import get_ipaddr_or_eppn, is_trusted_user

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
app.trusted_users = list()
if app.config.get('TRUSTED_USERS'):
    try:
        with open(app.config['TRUSTED_USERS']) as f:
            app.trusted_users = yaml.safe_load(f)['eppn']
        app.logger.info('Loaded trusted user list')
        app.logger.debug(f'Trusted user list: {app.trusted_users}')
    except IOError as e:
        app.logger.warning(f'Could not initialize trusted user list: {e}')

# Init MISP API
misp_api = MISPApi(config)

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
            result = misp_api.domain_name_lookup(original_domain_name)
            if not result:
                # Try searching for a less exact domain name
                parent_domain_name = '.'.join(original_domain_name.split('.')[1:])
                if parent_domain_name and domain(parent_domain_name):
                    result = misp_api.domain_name_lookup(parent_domain_name)
            return render_template(
                'index.jinja2',
                result=result,
                original_domain_name=original_domain_name,
                parent_domain_name=parent_domain_name,
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

        ret = misp_api.add_event(
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
