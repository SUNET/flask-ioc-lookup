#!/bin/bash

set -e
set -x

export DEBIAN_FRONTEND noninteractive

apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y \
      libpython3-dev \
      python3-venv \
      iputils-ping \
      procps \
      bind9-host \
      netcat-openbsd \
      net-tools \
      curl \
    && apt-get clean

rm -rf /var/lib/apt/lists/*

python3 -m venv /opt/flask-ioc-lookup/env
/opt/flask-ioc-lookup/env/bin/pip install -U pip
/opt/flask-ioc-lookup/env/bin/pip install --no-cache-dir -r /opt/flask-ioc-lookup/requirements.txt
/opt/flask-ioc-lookup/env/bin/pip freeze

useradd --system --shell /bin/false ioc
