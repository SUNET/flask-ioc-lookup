#!/bin/bash

set -e
set -x

export DEBIAN_FRONTEND noninteractive

/bin/sed -i s/deb.debian.org/ftp.se.debian.org/g /etc/apt/sources.list

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

python3 -m venv /opt/flask-rpz-lookup/env
/opt/flask-rpz-lookup/env/bin/pip install -U pip
/opt/flask-rpz-lookup/env/bin/pip install --no-cache-dir -r /opt/flask-rpz-lookup/requirements.txt
/opt/flask-rpz-lookup/env/bin/pip freeze

addgroup --system rpz

adduser --system --shell /bin/false rpz

