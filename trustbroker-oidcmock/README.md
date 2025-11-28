# OIDC Provider Mock

Mock OIDC Provider

# Authorization request

http://localhost:5050/oauth2/authorize?client_id=XTB-dev&redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug&scope=openid&response_type=code&response_mode=query&state=r964488b2aq&nonce=s3rtab2b8kk

# Token request

```
curl -v POST -d "userdata1=value1" -d "userdata2=value2" -d "client_id=XTB-dev" -d "client_secret=secret" -d "
grant_type=authorization_code" -d "redirect_uri=https%3A%2F%2Foidcdebugger.com%2Fdebug" -d "
code=oFc1F2R5IU4HBSAPOd3mk1xWs7BsFvhgOMoGWaTFogpkqRoeVfXNdXZxPt3Gn5yerpd1rsVu1cWmO1w_hZJ47DuWJqKWxjez8n_tjhBOdfGsaf4o3pVMimsQsQ5FlLMM"
-H 'Accept: application/x-www-form-urlencoded' 'http://localhost:5050/oauth2/token'
```

# Claims

Default claims:

- "sub": {USERNAME},
- "iss": "http://localhost:5050",
- "given_name": "{USERNAME}GivenName",
- "nonce": "jukpjn3rbz8",
- "sid": "O-XsEA14Rawk93MKo5SNCVMypo_af1s-jsD7fyeISqE",
- "aud": "XTB-dev",
- "azp": "XTB-dev",
- "auth_time": 1738330755,
- "exp": 1738332594,
- "iat": 1738330794,
- "family_name": "{USERNAME}FamilyName",
- "jti": "db1f1074-813f-451f-a2d7-7f21abd31c31",
- "email": "{USERNAME}@trustbroker.swiss

Custom claims: any /token request param
ex:

- "userdata1": "value1",
- "userdata2": "value2",
