#!/bin/bash
# Fast lane: Wire secrets into your docker-compose.yml and run it with 'docker-compose up' attached to console.
# Below we run it the correct way.

# get secrets
source env-vault.conf

# validate
[ ! -n "$STATECACHE_PASS" ] && echo "ERROR: STATECACHE_PASS undefined" && exit 1
[ ! -n "$PKI_PASSPHRASE" ] && echo "ERROR: PKI_PASSPHRASE undefined" && exit 1
if [ -z "$SSH_KEY" -a -z "$GIT_TOKEN" -a ! -r ssh/id_rsa -a ! -r ssh/git_token ]; then
	echo "INFO: Assuming public access to $GIT_URL"
	echo "HINT: GIT_TOKEN should be defined for private access via ENV or mapped to /etc/trustbroker/keys/git_token"
	echo "HINT: SSH_KEY should be defined for private access via ENV or mapped to /etc/trustbroker/keys/id_rsa"
fi

# run service mesh in foreground
docker compose up

# run service mesh in background and follow trustbroker log
#docker compose up -d
#docker logs -f trustbroker
