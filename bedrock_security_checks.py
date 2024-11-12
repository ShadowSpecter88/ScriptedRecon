import boto3
import pacu.core as core
from pacu.core.module import PacuModule

module = PacuModule(
    name="Bedrock Security Checks",
    description="Perform basic Bedrock and prompt injection security checks.",
    author="Your Name",
    date="2023-03-22",
)

module.add_command(
    name="check_open_s3_buckets",
    description="Check for open S3 buckets.",
    action=lambda: check_open_s3_buckets(module),
)

module.add_command(
    name="verify_iam_policy",
    description="Verify the proper configuration of IAM policies.",
    action=lambda: verify_iam_policy(module),
)

def check_open_s3_buckets(module):
    s3 = boto3.client("s3")
    buckets = s3.list_buckets()
    for bucket in buckets["Buckets"]:
        try:
            s3.head_bucket(Bucket=bucket["Name"])
            module.output(f"Bucket {bucket['Name']} is publicly accessible.")
        except Exception as e:
            module.output(f"Bucket {bucket['Name']} is not publicly accessible.")

def verify_iam_policy(module):
    iam = boto3.client("iam")
    policies = iam.list_policies()
    for policy in policies["Policies"]:
        policy_document = iam.get_policy(PolicyArn=policy["Arn"])["Policy"]["PolicyDocument"]
        if "bedrock" in policy_document or "prompt-injection" in policy_document:
            module.output(f"Policy {policy['Arn']} contains Bedrock or prompt injection references.")
        else:
            module.output(f"Policy {policy['Arn']} does not contain Bedrock or prompt injection references.")

if __name__ == "__main__":
    core.run_module(module)
