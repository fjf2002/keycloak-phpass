# Keycloak PHPass

A password hash provider to handle PHPass passwords inside Keycloak.

Makes it possible to migrate users and their existing PHPass hashed passwords from legacy databases.

## Build JAR

```bash
./gradlew assemble -Pdependency.keycloak.version=${KEYCLOAK_VERSION}
```

## Install

Copy the jar file (from `./build/libs`) to the keycloak providers directory. In the default Docker image this is at `/opt/keycloak/providers/`

Then restart Keycloak.

## Migrate Hashes into Keycloak

One strategy would be to build a script around these calls to import your hashes:

```shell
TOKEN=`curl --location --request POST 'https://keycloak.example.com/realms/master/protocol/openid-connect/token' --header 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'username=admin' --data-urlencode 'password=1234' --data-urlencode 'grant_type=password' --data-urlencode 'client_id=admin-cli' | jq -r '.access_token'`

# The `hashedSaltedValue` below corresponds to the password: "test"
curl 'https://keycloak.example.com/admin/realms/example_org/users/28e6ad26-41c6-4e5f-bc88-225cebb1cb61' -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data '{"requiredActions": ["UPDATE_PASSWORD"], "credentials": [ { "algorithm": "phpass", "hashedSaltedValue": "$S$Eph.xQb59uZylAYxOl4XfXelW/XWfTLLarPrfcS8bw33Rn5J9y2K", "hashIterations": 16, "type": "password", "salt":""}]}'
```
