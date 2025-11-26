#!/bin/bash

# Site config (you can also use shorter ecdsa keys, but git server need sto support it)
SSH_KEY_FILE=${SSH_KEY_FILE:-ssh/id_rsa}
SSH_KEY_OWNER=${SSH_KEY_OWNER:-xtb-owner@your.site}
SSH_CFG_FILE=${SSH_CFG_FILE:-ssh/config}

# SSH key is stored un-encrypted in vault (no apssword necessary)
SSH_KEY_PASS=

# Trusted server keys need to be engineered when StrictHostKeyChecking=yes is used
SSH_HST_FILE=${SSH_HST_FILE:-ssh/known_hosts}

# Generate client key
ssh-keygen -m pem -t rsa -b 4096 -P "$SSH_KEY_PASS" -f $SSH_KEY_FILE -C $SSH_KEY_OWNER

# Provide server trust: Done automatically when connecting to the Git server for the first time.
# To explicitly establish server trust setup keys/config and keys/known_hosts using OpenSSH conventions.
# The following default config allows bootstrapping any ssh server automatically, so take care what git url you are using.
touch $SSH_HST_FILE
cat >$SSH_CFG_FILE <<EOT
Host *
  StrictHostKeyChecking no
EOT

# Optional: Inject private key via ENV for bootstrap (done instead via volume mount from docker-compose or K8S secret)
SSH_KEY=$(cat $SSH_KEY_FILE | base64 -w 0)
[ -f env-vault.conf ] && sed -i.old -e "s|SSH_KEY=.*|SSH_KEY=$SSH_KEY|" env-vault.conf

# Put public key into Git server user or repository settings
echo "##### Public SSH key to be added to Git server user/repository #####"
cat ${SSH_KEY_FILE}.pub
