# Testing OPAL / OPA Authorization

## 1. Start the services
```bash
docker compose up -d
```
Wait a few seconds for OPAL Client to sync with OPAL Server and load the local git repository policy.

## 2. Test Permitted Request
The policy allows access if the `action` is `read`, `resource` is `finance`, and `user` is `finance_user`.

```bash
curl -i "http://localhost:8000/finance/1234?user_id=finance_user"
```

**Expected output:** HTTP 200 OK with the report data.

## 3. Test Denied Request
Any other user, action, or resource will be denied by default.

```bash
curl -i "http://localhost:8000/finance/1234?user_id=marketing_user"
```

**Expected output:** HTTP 403 Forbidden.

## 4. Test Service Unavailable
If OPAL Client is down, the dependency will handle it gracefully.
You can stop the opal-client container:
```bash
docker compose stop opal-client
```
Then try making the permitted request again:
```bash
curl -i "http://localhost:8000/finance/1234?user_id=finance_user"
```

**Expected output:** HTTP 503 Service Unavailable.
