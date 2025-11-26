#!/bin/bash
PERIOD=${1:-5}
while [ true ]; do
	curl -k -X POST http://localhost:8090/api/v1/config \
	     -H 'Content-Type: application/json' \
	     -d '{"action":"reload","adminSecret":"trustbroker.config.adminSecret"}'
	sleep $PERIOD
done
