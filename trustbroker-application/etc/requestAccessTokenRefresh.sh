#!/bin/bash

# Exchange a refresh token for a new access token.
curl \
--request POST \
--data 'client_id=XTB_demo-pkce&client_secret=secret&refresh_token=REFRESH_TOKEN_VALUE&grant_type=refresh_token' \
http://localhost:6060/realms/XTB_demo-pkce/openid-connect/token
