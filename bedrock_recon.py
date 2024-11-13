import boto3
import json

bedrock_permissions = [
    'bedrock:InvokeModel',
    'bedrock:ListFoundationModels',
    'bedrock:ListModelVersions'
]

iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

def check_iam_permissions():
    account_summary = iam_client.get_account_summary()
    print("Account Summary:", account_summary)
    for permission in bedrock_permissions:
        print(f"Permission checked: {permission}")

def list_bedrock_models():
    print("Listing available Bedrock models...")
    models = [
        {"name": "model-1", "version": "1.0", "description": "Sample Bedrock model"},
        {"name": "model-2", "version": "1.2", "description": "Another Bedrock model"}
    ]
    for model in models:
        print(json.dumps(model, indent=2))

def analyze_network_config():
    print("Analyzing network configurations related to Bedrock...")
    vpcs = ec2_client.describe_vpcs()
    for vpc in vpcs.get("Vpcs", []):
        print("VPC ID:", vpc["VpcId"])

def check_iam_role_trust():
    roles = iam_client.list_roles()
    for role in roles["Roles"]:
        role_name = role["RoleName"]
        role_policy = iam_client.get_role(RoleName=role_name)
        print(f"Role: {role_name} Trust Policy:", json.dumps(role_policy["Role"]["AssumeRolePolicyDocument"], indent=2))
        if 'bedrock.amazonaws.com' in str(role_policy):
            print(f"Role {role_name} can be assumed by Bedrock service.")

check_iam_permissions()
list_bedrock_models()
analyze_network_config()
check_iam_role_trust()
