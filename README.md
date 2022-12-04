
```
curl --insecure -H "Content-Type: application/json; charset=utf-8" \
-X POST \
-H 'Authorization: Bearer ab2316584873095f017f6dfa7a9415794f563fcc473eb3fe65b9167e37fd5a4b' \
-d '{"status":200,"document":{"login_id":"wonkwonkwonk","login_type":"id","password":{"value":"asdfasdfasdf"},"personal":{"first_name":"wonk","last_name":"sun","birth_year":2002,"birth_month":1,"birth_day":2,"gender":"M","nationality":"KOR"},"emails":[{"email":"wonk@wonk.orgg","priority":0}]}}' \
http://localhost:8080/v1/user

curl --insecure -H "Content-Type: application/json; charset=utf-8" \
-X GET \
https://localhost:5558/auth/wait/1234
```

## Google oidc
- set access_type to offline
- need to re-prompt consent, to get refresh token if you've already been authorized.

##
curl --insecure -H "Content-Type: application/json; charset=utf-8" \
-X GET \
-H 'Authorization: Bearer ab2316584873095f017f6dfa7a9415794f563fcc473eb3fe65b9167e37fd5a4b' \
'https://localhost:5558/v1/auth/request/google'

curl --insecure -H "Content-Type: application/json; charset=utf-8" \
-X GET \
-H 'Authorization: Bearer ab2316584873095f017f6dfa7a9415794f563fcc473eb3fe65b9167e37fd5a4b' \
'https://localhost:5558/v1/auth/authorize/google/a4630da1-f013-4e9f-a1d7-b3f6baad79b6'