FALCON_CLIENT_ID=something
FALCON_CLIENT_SECRET=something
FALCON_API_BASEURL=https://api.crowdstrike.com

curl -X POST "${FALCON_API_BASEURL}/oauth2/token" \
 -H "accept: application/json" \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "client_id=${FALCON_CLIENT_ID}" \
 -d "client_secret=${FALCON_CLIENT_SECRET}" > 0-token.json

AUTH_TOKEN=$(cat 0-token.json | jq -r '.access_token')

curl -X GET "${FALCON_API_BASEURL}/detects/queries/iom/v2" \
    -H "Authorization: bearer ${AUTH_TOKEN}" \
    -H "accept: application/json" > 1-detects_queries_iom_v2.json

curl -X GET "${FALCON_API_BASEURL}/detects/entities/iom/v1" \
    -H "Authorization: bearer ${AUTH_TOKEN}" \
    -H "accept: application/json" > 1-detects_entities_iom_v1.json

RESOURCE_1=$(cat 1-detects_queries_iom_v2.json | jq -r '.resources[0]')

curl -X GET "${FALCON_API_BASEURL}/detects/entities/iom/v2?ids=${RESOURCE_1}" \
    -H "Authorization: bearer ${AUTH_TOKEN}" \
    -H "accept: application/json" > 2-detects_entities_iom_v2_ids=${RESOURCE_1}.json

POLICY_ID=$(cat 2-detects_entities_iom_v2_ids=${RESOURCE_1}.json | jq -r '.resources[0].policy_id')

curl -X GET "${FALCON_API_BASEURL}/settings/entities/policy-details/v2?ids=${POLICY_ID}" \
    -H "Authorization: bearer ${AUTH_TOKEN}" \
    -H "accept: application/json" > 3-settings_entities_policy_details_v2_ids=${POLICY_ID}.json

curl -X GET "${FALCON_API_BASEURL}/settings/entities/policy/v1" \
    -H "Authorization: bearer ${AUTH_TOKEN}" \
    -H "accept: application/json"> 4-settings_entities_policy_v1.json

#curl -X GET "${FALCON_API_BASEURL}/settings/entities/policy/v1?policy-id=${POLICY_ID}" \
#    -H "Authorization: bearer ${AUTH_TOKEN}" \
#    -H "accept: application/json"> 4-settings_entities_policy_v1_policy-id=${POLICY_ID}.json
