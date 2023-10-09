SOURCE=ioc_lookup scripts
PYTHON=$(shell which python)
PIPCOMPILE=pip-compile --verbose --generate-hashes --upgrade --extra-index-url https://pypi.sunet.se/simple
PIPSYNC=pip-sync --index-url https://pypi.sunet.se/simple --python-executable $(PYTHON)
MYPY_ARGS=--install-types --non-interactive --pretty --ignore-missing-imports --warn-unused-ignores

reformat:
	isort --line-width 120 --atomic --project eduid_common $(SOURCE)
	black --line-length 120 --target-version py39 $(SOURCE)

typecheck:
	mypy $(MYPY_ARGS) $(SOURCE)

test:
	PYTHONPATH=$(SRCDIR) pytest -vvv -ra --log-cli-level DEBUG

docker_image:
	docker build -t docker.sunet.se/sunet/flask-ioc-lookup .

docker_push:
	docker push docker.sunet.se/sunet/flask-ioc-lookup:latest

%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))

dev_sync_deps:
	$(PIPSYNC) test_requirements.txt
