import os
from falconpy import CSPMRegistration, APIHarnessV2
import logging
import json, csv

# Authenticate
falcon = APIHarnessV2(client_id=os.getenv("FALCON_CLIENT_ID"),
                      client_secret=os.getenv("FALCON_CLIENT_SECRET")
                      )

# Get list of all policies and details and output all to JSON file
policy_details_all = falcon.command("GetCSPMPolicySettings")
with open('policy_details_all.json', 'w') as policy_details_all_file:
    policy_details_all_file.write("%s\n" % json.dumps(policy_details_all, indent=2))


# Now to make a CSV with just some parts of the data
# Create CSV header
column_headers = ['name', 'cloud_provider', 'cloud_service_friendly', 'cloud_service', 'cloud_service_subtype', 'policy_type', 'severity', 'default_severity', 'is_remediable' ]
with open('policy_names_and_service.csv', 'w') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames = column_headers)
    writer.writeheader()

# Find matches and output value in CSV
for policy_details in policy_details_all["body"]["resources"]:
    policy_details_and_benchmark_ids = {key: value for key, value in policy_details.items() if "name" in key or "cloud_provider" in key or "cloud_service" in key or "policy_type" in key or "severity" in key or "default_severity" in key or "is_remediable" in key}
    print(policy_details_and_benchmark_ids)
    with open('policy_names_and_service.csv', 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames = column_headers)
        writer.writerow(policy_details_and_benchmark_ids)
  