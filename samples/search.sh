#!/bin/bash

API-TOKEN=<APITOKEN>
ENDPOINT="https://<IOC_LOOKUP_URL>"

CURL=`which curl`
JQ=`which jq`

$CURL -s -X POST \
	-H "Accept: application/json" \
	-H "Content-Type: application/json" \
	-H "API-TOKEN: ${API_TOKEN}" \
	$ENDPOINT --data "{ \"search\": \"${1}\" }" \
	| $JQ '.result[].event_id'
