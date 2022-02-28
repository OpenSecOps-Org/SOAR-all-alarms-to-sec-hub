import os
import re
import boto3


sts_client = boto3.client('sts')

ALARM_TYPE = os.environ['ALARM_TYPE']
COMPANY_NAME = os.environ['COMPANY_NAME']


def lambda_handler(event, _context):
    """Reacting to CloudWatch Alarm State Change events"""
    print(event)

    finding_id = event['id']
    account_id = event['account']
    region = event['region']
    timestamp = event['time']

    detail = event['detail']
    title = detail['alarmName']
    description = detail['configuration'].get('description', 'N/A')

    if "CIS-" in title:
        print(f"Suppressing CIS alarm '{title}'.")
        return

    match = re.search(
        "(^|-)(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)(-|$)", title)
    if not match:
        #severity = "INFORMATIONAL"
        print(
            f"The alarm name '{title}' contains no severity (INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL). Ignoring the alarm entirely.")
        return

    severity = match.group().strip('-')

    incident_domain = "APP"
    if "INFRA" in title:
        incident_domain = "INFRA"

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": title,
        "AwsAccountId": account_id,
        "Types": [
            f"Software and Configuration Checks/CloudWatch Alarms/{ALARM_TYPE}",
        ],
        "CreatedAt": timestamp,
        "UpdatedAt": timestamp,
        "Severity": {
            "Label": severity
        },
        "Title": title,
        "Description": description,
        "Resources": [
            {
                "Type": "AwsAccountId",
                "Id": account_id,
                "Region": region,
            },
        ],
        "ProductFields": {
            "aws/securityhub/FindingId": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default/{finding_id}",
            "aws/securityhub/ProductName": "Default",
            "aws/securityhub/CompanyName": COMPANY_NAME,
            "TicketDestination": "TEAM",
            "IncidentDomain": incident_domain
        },
        "VerificationState": "TRUE_POSITIVE",
        "Workflow": {
            "Status": "NEW"
        },
        "RecordState": "ACTIVE"
    }

    print(
        f"Creating {severity} incident for {incident_domain} alarm '{title}'")
    client = get_client('securityhub', account_id, region)
    response = client.batch_import_findings(Findings=[finding])
    if response['FailedCount'] != 0:
        print(f"The finding failed to import: '{response['FailedFindings']}'")
    else:
        print("Finding imported successfully.")

    return True


def get_client(client_type, account_id, region, role='SecurityHubRole'):
    other_session = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role}",
        RoleSessionName=f"cross_acct_lambda_session_{account_id}"
    )
    access_key = other_session['Credentials']['AccessKeyId']
    secret_key = other_session['Credentials']['SecretAccessKey']
    session_token = other_session['Credentials']['SessionToken']
    return boto3.client(
        client_type,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )
