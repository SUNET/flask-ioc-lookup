# -*- coding: utf-8 -*-

import sys
from datetime import datetime
from os import environ

import yaml
from flask import Flask, render_template, request, current_app
from flask_limiter import Limiter
from validators import domain
from whitenoise import WhiteNoise

from rpz_lookup.misp_api import MISPApi
from rpz_lookup.util import get_ipaddr_or_eppn

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


# Init MISP API
misp_api = MISPApi(config)

# Init rate limiting
limiter = Limiter(app, key_func=get_ipaddr_or_eppn)


def rate_limit_from_config():
    return app.config.get('REQUEST_RATE_LIMIT', '1/second')


@app.template_filter('ts')
def _jinja2_filter_ts(ts: str):
    dt = datetime.utcfromtimestamp(int(ts))
    fmt='%Y-%m-%d %H:%M:%S'
    return dt.strftime(fmt)


# Views
@app.route('/', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def index():
    error = None
    if request.method == 'POST':
        domain_name = request.form.get('domain_name')
        if domain_name and domain(domain_name):
            result = misp_api.domain_name_lookup(domain_name)
            return render_template('index.jinja2', result=result, domain_name=domain_name, user=get_ipaddr_or_eppn())
        error = f'Invalid domain name: "{domain_name}"'

    return render_template('index.jinja2', error=error, user=get_ipaddr_or_eppn())


@app.route('/report', methods=['GET', 'POST'])
@limiter.limit(rate_limit_from_config)
def report():
    if request.method == 'POST':
        form_input = request.form.get('domain_names').split('\n')
        domain_names = []
        for domain_name in form_input:
            if domain_name:
                domain_name = ''.join(domain_name.split())  # Normalize whitespace
                if not domain(domain_name):
                    return render_template('report.jinja2', error=f'Invalid domain name: "{domain_name}"',
                                           user=get_ipaddr_or_eppn())
                domain_names.append(domain_name)

        if not domain_names:
            error = f'No valid domain name found'
            return render_template('report.jinja2', error=error, user=get_ipaddr_or_eppn())

        reporter = get_ipaddr_or_eppn()
        tags = ['OSINT', 'TLP:GREEN']
        ret = misp_api.add_event(domain_names=domain_names, info='From flask_rpz_lookup',
                                 tags=tags, comment=f'Reported by {reporter}', to_ids=True)
        current_app.logger.debug(ret)
        result = 'success'
        return render_template('report.jinja2', result=result, domain_names=domain_names, user=get_ipaddr_or_eppn())
    return render_template('report.jinja2', user=get_ipaddr_or_eppn())


if __name__ == '__main__':
    app.run()
