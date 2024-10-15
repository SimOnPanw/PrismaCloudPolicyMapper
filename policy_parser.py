import json
import csv
import os
import requests
import argparse
import logging
from dotenv import load_dotenv

# Create a logger object
logger = logging.getLogger()


def filter_policies_by_standard(policies, standard_name):
    filtered_policies = []
    
    for policy in policies:
        if 'complianceMetadata' in policy:
            for compliance in policy['complianceMetadata']:
                if compliance.get('standardName') == standard_name:
                    filtered_policies.append({
                        'policy_name': f'"{policy["name"]}"',
                        'labels': '"Custom"',
                        'compliance_framework': f'"{compliance.get("standardName")}"',
                        'compliance_requirement': f'"{compliance.get("requirementId")}"',
                        'compliance_section': f'"{compliance.get("sectionId")}"',
                        'status': 'true'
                    })
    return filtered_policies

def write_policies_to_csv(filtered_policies, output_csv):
    fieldnames = ['policy_name', 'labels', 'compliance_framework', 'compliance_requirement', 'compliance_section', 'status']
    
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for policy in filtered_policies:
            writer.writerow(policy)

# Print the name of each policy where cloudType is AWS, policySubTypes contains "run", and policyMode is "redlock_default"
def print_parsed_policies(policies):
    for policy in policies:
        # if (policy.get('cloudType') == 'aws' and
        #     'run' in policy.get('policySubTypes', []) and
        #     policy.get('policyMode') == 'redlock_default'):
        #     print(policy['name'])
        if ('iam' in policy.get('policyType', []) and
            policy.get('policyMode') == 'redlock_default'):
            logger.info(f"{policy['name']};{policy['cloudType']};{policy['policyCategory']};{policy['policyClass']};{policy['remediable']}") 

            
def get_policies(base_url, token):
    url = f"https://{base_url}/v2/policy"
    headers = {"content-type": "application/json; charset=UTF-8", "x-redlock-auth": token}
   
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        logger.error(f"Exception in get_policies: {err}")
        return None

    response_json = response.json()

    logger.debug(f"Response status code: {response.status_code}")
    logger.debug(f"Response headers: {response.headers}")    
    return response_json


def get_compute_url(base_url, token):
    url = f"https://{base_url}/meta_info"
    headers = {"content-type": "application/json; charset=UTF-8", "Authorization": "Bearer " + token}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except requests.exceptions.RequestException as err:
        logger.error("Oops! An exception occurred in get_compute_url, ", err)
        return None

    response_json = response.json()
    return response_json.get("twistlockUrl", None)


def login_saas(base_url, access_key, secret_key):
    url = f"https://{base_url}/login"
    payload = json.dumps({"username": access_key, "password": secret_key})
    headers = {"content-type": "application/json; charset=UTF-8"}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
    except Exception as e:
        logger.info(f"Error in login_saas: {e}")
        return None

    return response.json().get("token")


def login_compute(base_url, access_key, secret_key):
    url = f"{base_url}/api/v1/authenticate"

    payload = json.dumps({"username": access_key, "password": secret_key})
    headers = {"content-type": "application/json; charset=UTF-8"}
    response = requests.post(url, headers=headers, data=payload)
    return response.json()["token"]

# Main function
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    input_csv_file = 'processed_policies_output.csv'    
    if args.debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    logging.basicConfig(
        level=logging_level, format="%(asctime)s - %(levelname)s - %(message)s", filename="app.log", filemode="a"
    )

    # Create a console handler
    console_handler = logging.StreamHandler()

    # Add the console handler to the logger
    logger.addHandler(console_handler)

    logger.info("======================= START =======================")
    logger.debug("======================= DEBUG MODE =======================")

    load_dotenv()

    url = os.environ.get("PRISMA_API_URL")
    identity = os.environ.get("PRISMA_ACCESS_KEY")
    secret = os.environ.get("PRISMA_SECRET_KEY")

    if not url or not identity or not secret:
        logger.error("PRISMA_API_URL, PRISMA_ACCESS_KEY, PRISMA_SECRET_KEY variables are not set.")
        return

    token = login_saas(url, identity, secret)
    # compute_url = get_compute_url(url, token)
    # compute_token = login_compute(compute_url, identity, secret)
    # logger.debug(f"Compute url: {compute_url}")

    if token is None:
        logger.error("Unable to authenticate.")
        return  
    
    policies = get_policies(url, token)
    
    # print_parsed_policies(policies)
    # Specify the standard name to filter by
    standard_name = 'CIS v1.2.0 (Azure)'  # Replace with your desired standard_name

    # Filter policies based on complianceMetadata standardName
    filtered_policies = filter_policies_by_standard(policies, standard_name)

    # Output CSV file
    output_csv_file = 'filtered_policies.csv'
    
    # Write filtered policies to CSV
    write_policies_to_csv(filtered_policies, output_csv_file)
    print(f"Filtered policies saved to {output_csv_file}")


if __name__ == "__main__":
    main()
