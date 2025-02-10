import os
from falconpy import CSPMRegistration, APIHarnessV2
import logging
import json, csv
from jsonpath_ng import jsonpath, parse, ext
import pandas as pd
from collections import defaultdict

def safe_get(dict_obj, key, default=""):
    """Safely get a value from a dictionary with a default if key doesn't exist"""
    return str(dict_obj.get(key, default))
def process_benchmark_data(policy_details_all_json, output_file='benchmarks_all.csv'):
    # Define headers with no duplicates
    headers = [
        "benchmark", "id", "benchmark_short", "recommendation_number",
        "policy_id", "name", "is_remediable", "created_at", "updated_at",
        "policy_type", "cloud_service_subtype", "cloud_service",
        "cloud_service_friendly", "cloud_asset_type", "cloud_asset_type_id",
        "cloud_provider", "default_severity", "policy_timestamp"
    ]
    
    # Create a DataFrame to store all benchmark data
    df = pd.DataFrame(columns=headers)
    
    # Process all resources directly instead of using jsonpath
    rows = []
    resources = policy_details_all_json['body']['resources']
    
    for policy in resources:
        # Check each type of benchmark
        benchmark_types = [
            ("CIS", "cis_benchmark"),
            ("CISA", "cisa_benchmark"),
            ("HIPAA", "hipaa_benchmark"),
            ("HITRUST", "hitrust_benchmark"),
            ("ISO", "iso_benchmark"),
            ("NIST", "nist_benchmark"),
            ("PCI", "pci_benchmark"),
            ("SOC2", "soc2_benchmark")
        ]
        
        for benchmark_name, benchmark_key in benchmark_types:
            # Check if this benchmark type exists in the policy
            if benchmark_key in policy and policy[benchmark_key]:
                # Process all benchmark entries for this type
                for benchmark_entry in policy[benchmark_key]:
                    row = {
                        "benchmark": benchmark_name,
                        "id": benchmark_entry.get("id", ""),
                        "benchmark_short": benchmark_entry.get("benchmark_short", ""),
                        "recommendation_number": benchmark_entry.get("recommendation_number", ""),
                        "policy_id": safe_get(policy, "policy_id"),
                        "name": safe_get(policy, "name"),
                        "is_remediable": safe_get(policy, "is_remediable"),
                        "created_at": safe_get(policy, "created_at"),
                        "updated_at": safe_get(policy, "updated_at"),
                        "policy_type": safe_get(policy, "policy_type"),
                        "cloud_service_subtype": safe_get(policy, "cloud_service_subtype"),
                        "cloud_service": safe_get(policy, "cloud_service"),
                        "cloud_service_friendly": safe_get(policy, "cloud_service_friendly"),
                        "cloud_asset_type": safe_get(policy, "cloud_asset_type"),
                        "cloud_asset_type_id": safe_get(policy, "cloud_asset_type_id"),
                        "cloud_provider": safe_get(policy, "cloud_provider"),
                        "default_severity": safe_get(policy, "default_severity"),
                        "policy_timestamp": safe_get(policy, "policy_timestamp")
                    }
                    rows.append(row)
    
    # Convert to DataFrame and write to CSV
    df = pd.DataFrame(rows)
    print(f"Total rows processed: {len(df)}")  # Debug information
    df.to_csv(output_file, index=False, quoting=csv.QUOTE_ALL)
    return df

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
    #print(policy_details_and_benchmark_ids)
    with open('policy_names_and_service.csv', 'a') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames = column_headers)
        writer.writerow(policy_details_and_benchmark_ids)

policy_details_all_json = json.loads(json.dumps(policy_details_all, indent=2))
df = process_benchmark_data(policy_details_all_json, 'benchmarks_all.csv')