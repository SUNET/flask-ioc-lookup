# -*- coding: utf-8 -*-

import sys
import yaml
from os import environ
from datetime import datetime
from flask import Flask, render_template, request
from whitenoise import WhiteNoise
from validators import domain
from flask_limiter import Limiter
from flask_limiter.util import get_ipaddr

from rpz_lookup.misp_api import MISPApi

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
app.wsgi_app = WhiteNoise(app.wsgi_app, root=config.get('STATIC_FILES', 'rpz_lookup/static/'))

# Init MISP API
misp_api = MISPApi(config)

# Init rate limiting
limiter = Limiter(app, key_func=get_ipaddr)


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
            #result = misp_api.search(type='org_id', value='*')
            return render_template('index.jinja2', result=result)
        error = 'Invalid domain name'

    return render_template('index.jinja2', error=error)


if __name__ == '__main__':
    app.run()
