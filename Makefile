SOURCE=ioc_lookup scripts
UV=$(shell which uv)
PIPCOMPILE=$(UV) pip compile --upgrade --generate-hashes --no-strip-extras --index-url https://pypi.sunet.se/simple --emit-index-url
PIPSYNC=$(UV) pip sync --index-url https://pypi.sunet.se/simple
MYPY_ARGS=--install-types --non-interactive --pretty --ignore-missing-imports --warn-unused-ignores

reformat:
	# sort imports and remove unused imports
	ruff check --select F401,I --fix
	# reformat
	ruff format
	# make an extended check with rules that might be triggered by reformat
	ruff check --config ruff.toml

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
