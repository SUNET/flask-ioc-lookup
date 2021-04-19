#!/bin/sh

set -e
set -x

. /opt/flask-ioc-lookup/env/bin/activate

project_dir=${project_dir-"/opt/flask-ioc-lookup/"}
# gunicorn settings
workers=${workers-1}
worker_class=${worker_class-sync}
worker_threads=${worker_threads-1}
worker_timeout=${worker_timeout-30}
# Need to tell Gunicorn to trust the X-Forwarded-* headers
forwarded_allow_ips=${forwarded_allow_ips-'*'}

# set PYTHONPATH if it is not already set using Docker environment
export PYTHONPATH=${PYTHONPATH-${project_dir}}

# nice to have in docker run output, to check what
# version of something is actually running.
/opt/flask-ioc-lookup/env/bin/pip freeze

echo ""
echo "$0: Starting ioc_lookup"

exec start-stop-daemon --start -c ioc:ioc --exec \
     /opt/flask-ioc-lookup/env/bin/gunicorn \
     --user=ioc --group=ioc -- \
     --bind 0.0.0.0:5000 \
     --workers ${workers} --worker-class ${worker_class} \
     --threads ${worker_threads} --timeout ${worker_timeout} \
     --forwarded-allow-ips="${forwarded_allow_ips}" \
     ioc_lookup.app:app
