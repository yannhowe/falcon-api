# CSPM API

## Quickstart

### Sample Data
To quickly get some sample data use the bash script to see if the API is returning what you need.

Fill up the variables `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_API_BASEURL` and you should be good to go if you have the correct API scopes.
```
./sample_data.sh
```

The file output is named after the endpoint and will contain the API response.
```
me@ABC bash % ls
0-token.json
1-detects_entities_iom_v1.json
1-detects_queries_iom_v2.json
2-detects_entities_iom_v2_ids=641a84c92508a1d8b7f84575_267a132636abd2f8ed8f9fc107bc3eb1671fc1bd00c4f1aeb40741150a490e32.json
2-detects_entities_iom_v2_ids=ff23acc17c5a5f28ab56bb34_f8b9f76b86207c538d9cd9bc0c14dea86460cb3d1e811335f07f3a75659723f7.json
3-settings_entities_policy_details_v2_ids=925.json
4-settings_entities_policy_v1.json
4-settings_entities_policy_v1_policy-id=925.json
sample_data.sh
```

### Policy Data
I needed a list of all policies 
- To quickly find policies to match them to prospect requirements
- To map Benchmark Section to Crowdstrike Policy ID
- To provide prospects a feel of what we check for

I use [pipenv](https://pipenv.pypa.io/en/latest/installation.html) but there is a `requirements.txt` if you need.

```
pipenv install
pipenv run python get-policy-list.py
```

output
```
me@ABC get-policy-data % ls
Pipfile                         Pipfile.lock                    get-policy-list.py              policy_details_all.json         policy_names_and_service.csv    requirements.txt
```