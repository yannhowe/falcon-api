import os
from falconpy import CSPMRegistration, APIHarnessV2
import logging
import json, csv
from jsonpath_ng import jsonpath, parse, ext
import pandas as pd
from collections import defaultdict


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

## Test jsonpath
#jsonpath_expression_test = ext.parse("$.body.resources[?(@.cis_benchmark[*])]")
#for match in jsonpath_expression_test.find(policy_details_all_json):
#    print(match.value["cis_benchmark"][0]["id"])
 

## Get list of benchmarks in bash
# cat policy_details_all.json| grep _benchmark | awk -F"\"" '{print $2}' | sort --unique

jsonpath_expression_cis_benchmark = ext.parse("$.body.resources[?(@.cis_benchmark[*])]")
jsonpath_expression_cisa_benchmark = ext.parse("$.body.resources[?(@.cisa_benchmark[*])]")
jsonpath_expression_hipaa_benchmark = ext.parse("$.body.resources[?(@.hipaa_benchmark[*])]")
jsonpath_expression_hitrust_benchmark = ext.parse("$.body.resources[?(@.hitrust_benchmark[*])]")
jsonpath_expression_iso_benchmark = ext.parse("$.body.resources[?(@.iso_benchmark[*])]")
jsonpath_expression_nist_benchmark = ext.parse("$.body.resources[?(@.nist_benchmark[*])]")
jsonpath_expression_pci_benchmark = ext.parse("$.body.resources[?(@.pci_benchmark[*])]")
jsonpath_expression_soc2_benchmark = ext.parse("$.body.resources[?(@.soc2_benchmark[*])]")




with open('benchmarks_all.csv', 'w') as benchmarks_all_file:
    benchmarks_all_file.write("benchmark,id,benchmark_short,recommendation_number,policy_id,name,is_remediable,created_at,updated_at,policy_id,name,policy_type,cloud_service_subtype,cloud_service,cloud_service_friendly,cloud_asset_type,cloud_asset_type_id,cloud_provider,default_severity,policy_timestamp\n")
    for match in jsonpath_expression_cis_benchmark.find(policy_details_all_json):
        age = match.value.setdefault("cloud_service_subtype", "")
        benchmarks_all_file.write("\"CIS\",\"" + str(match.value["cis_benchmark"][0]["id"]) + "\",\"" + match.value["cis_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["cis_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + "\",\"" + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_cisa_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"CISA\",\"" + str(match.value["cisa_benchmark"][0]["id"]) + "\",\"" + match.value["cisa_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["cisa_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_hipaa_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"HIPAA\",\"" + str(match.value["hipaa_benchmark"][0]["id"]) + "\",\"" + match.value["hipaa_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["hipaa_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_hitrust_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"HITRUST\",\"" + str(match.value["hitrust_benchmark"][0]["id"]) + "\",\"" + match.value["hitrust_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["hitrust_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_iso_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"ISO\",\"" + str(match.value["iso_benchmark"][0]["id"]) + "\",\"" + match.value["iso_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["iso_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_nist_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"NIST\",\"" + str(match.value["nist_benchmark"][0]["id"]) + "\",\"" + match.value["nist_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["nist_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_pci_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"PCI\",\"" + str(match.value["pci_benchmark"][0]["id"]) + "\",\"" + match.value["pci_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["pci_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")
    for match in jsonpath_expression_soc2_benchmark.find(policy_details_all_json):
        benchmarks_all_file.write("\"SOC2\",\"" + str(match.value["soc2_benchmark"][0]["id"]) + "\",\"" + match.value["soc2_benchmark"][0]["benchmark_short"] + "\",\"" + match.value["soc2_benchmark"][0]["recommendation_number"] + "\",\"" + str(match.value["policy_id"]) + "\",\"" + match.value["name"] + str(match.value["is_remediable"]) + "\",\"" + str(match.value["created_at"]) + "\",\"" + str(match.value["updated_at"]) + "\",\"" + str(match.value["policy_id"]) + "\",\"" + str(match.value["name"]) + "\",\"" + str(match.value["policy_type"]) + "\",\"" + str(match.value["cloud_service_subtype"]) + "\",\"" + str(match.value["cloud_service"]) + "\",\"" + str(match.value["cloud_service_friendly"]) + "\",\"" + str(match.value["cloud_asset_type"]) + "\",\"" + str(match.value["cloud_asset_type_id"]) + "\",\"" + str(match.value["cloud_provider"]) + "\",\"" + str(match.value["default_severity"]) + "\",\"" + str(match.value["policy_timestamp"]) + "\"\n")