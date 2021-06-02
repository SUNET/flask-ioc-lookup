SOURCE=ioc_lookup scripts
PIPCOMPILE=pip-compile --generate-hashes --upgrade --extra-index-url https://pypi.sunet.se/simple

reformat:
	isort --line-width 120 --atomic --project eduid_common $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

docker_image:
	docker build -t docker.sunet.se/sunet/flask-ioc-lookup .

docker_push:
	docker push docker.sunet.se/sunet/flask-ioc-lookup:latest


%ments.txt: %ments.in
	CUSTOM_COMPILE_COMMAND="make update_deps" $(PIPCOMPILE) $< > $@

update_deps: $(patsubst %ments.in,%ments.txt,$(wildcard *ments.in))
