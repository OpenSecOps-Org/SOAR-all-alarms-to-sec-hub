"""
CloudWatch Alarms to Security Hub Integration

This Lambda function transforms CloudWatch alarm state change events into Security Hub findings
with enhanced resource information extraction for SOAR processing.

Key Features:
- Extracts monitored AWS resources (Step Functions, Lambda) from alarm configuration
- Creates ASFF-compliant Security Hub findings with origin account tracking
- Supports cross-account operation via role assumption
- Filters CIS alarms and enforces severity requirements
- Robust error handling maintains backward compatibility

Environment Variables:
- ALARM_TYPE: Type identifier for Security Hub finding classification
- COMPANY_NAME: Company name for Security Hub metadata

Author: OpenSecOps SOAR Team
"""

import os
import re
import boto3
from typing import Dict, Any, Optional

# Global AWS clients and configuration
sts_client = boto3.client('sts')

# Environment configuration
ALARM_TYPE = os.environ['ALARM_TYPE']  # e.g., 'soar-cloudwatch-alarms'
COMPANY_NAME = os.environ['COMPANY_NAME']  # e.g., 'OpenSecOps SOAR'


def extract_monitored_resource(detail, account_id, region):
    """Extract monitored resource from CloudWatch alarm configuration
    
    Analyzes the alarm's namespace and dimensions to identify the actual AWS resource
    being monitored, enabling SOAR to process incidents with specific resource ARNs
    instead of relying on alarm name parsing.
    
    Supported Services:
        AWS/States: Step Functions state machines (extracts StateMachineArn)
        AWS/Lambda: Lambda functions (constructs ARN from FunctionName)
    
    Args:
        detail (dict): CloudWatch alarm detail section from EventBridge event
        account_id (str): AWS account ID where alarm originated
        region (str): AWS region where alarm is configured
        
    Returns:
        dict: ASFF Resource dict with Type, Id, Region fields, or None if:
              - Unsupported service namespace
              - Missing/malformed configuration
              - Any extraction error (maintains backward compatibility)
              
    Example Returns:
        Step Functions: {'Type': 'AwsStatesStateMachine', 'Id': 'arn:aws:states:...', 'Region': 'us-east-1'}
        Lambda: {'Type': 'AwsLambdaFunction', 'Id': 'arn:aws:lambda:...', 'Region': 'us-east-1'}
        Unsupported: None
    """
    try:
        # Extract alarm configuration with safe defaults
        config = detail.get('configuration', {})
        namespace = config.get('namespace', '')  # e.g., 'AWS/States', 'AWS/Lambda'
        dimensions = config.get('dimensions', [])  # List of name/value dimension pairs
        
        # Validate dimensions structure to prevent crashes
        if not isinstance(dimensions, list):
            print(f"Warning: dimensions is not a list: {type(dimensions)}")
            return None
        
        # Process Step Functions state machine alarms
        if namespace == 'AWS/States':
            for dim in dimensions:
                if not isinstance(dim, dict):
                    continue  # Skip malformed dimension entries
                    
                # Look for StateMachineArn dimension containing the full ARN
                if dim.get('name') == 'StateMachineArn':
                    state_machine_arn = dim.get('value')
                    if state_machine_arn and isinstance(state_machine_arn, str):
                        return {
                            'Type': 'AwsStatesStateMachine',
                            'Id': state_machine_arn,  # Already a full ARN
                            'Region': region
                        }
        
        # Process Lambda function alarms        
        elif namespace == 'AWS/Lambda':
            for dim in dimensions:
                if not isinstance(dim, dict):
                    continue  # Skip malformed dimension entries
                    
                # Look for FunctionName dimension and construct full ARN
                if dim.get('name') == 'FunctionName':
                    function_name = dim.get('value')
                    if function_name and isinstance(function_name, str):
                        # Construct full Lambda function ARN from name
                        function_arn = f"arn:aws:lambda:{region}:{account_id}:function:{function_name}"
                        return {
                            'Type': 'AwsLambdaFunction',
                            'Id': function_arn,
                            'Region': region
                        }
        
        # Unsupported namespace, missing dimensions, or no matching dimension found
        return None
        
    except Exception as e:
        # Log error but never crash - maintain backward compatibility
        print(f"Error extracting monitored resource: {str(e)}")
        return None


def lambda_handler(event, _context):
    """Process CloudWatch Alarm State Change events and create Security Hub findings
    
    Main entry point for the Lambda function. Transforms CloudWatch alarm events
    from EventBridge into ASFF-compliant Security Hub findings with enhanced
    resource information for SOAR processing.
    
    Event Processing Flow:
    1. Extract alarm metadata (account, region, severity, description)
    2. Apply filtering rules (suppress CIS alarms, require severity)
    3. Extract monitored resource information (Step Functions, Lambda)
    4. Build ASFF-compliant Security Hub finding
    5. Publish finding via cross-account role assumption
    
    Args:
        event (dict): EventBridge CloudWatch Alarm State Change event
        _context: Lambda context (unused)
        
    Returns:
        bool: True if finding published successfully, None if suppressed
        
    Raises:
        Exception: Re-raises any unhandled errors after logging
    """
    print(f"Processing CloudWatch alarm event: {event}")  # Full event for debugging

    # Extract core event metadata
    finding_id = event['id']  # Unique event ID for Security Hub finding
    account_id = event['account']  # Origin account where alarm fired
    region = event['region']  # AWS region of the alarm
    
    # Use actual alarm state change timestamp, fallback to event timestamp
    alarm_timestamp = extract_alarm_timestamp(event)
    event_timestamp = event['time']  # EventBridge processing timestamp

    # Extract alarm details
    detail = event['detail']
    title = detail['alarmName']  # Alarm name containing severity and service info
    description = detail['configuration'].get('description', 'N/A')  # Human-readable description

    # Apply filtering rules - suppress specific alarm types
    if "CIS-" in title:
        print(f"Suppressing CIS alarm '{title}' (CIS alarms are handled separately)")
        return

    # Extract severity from alarm name - required for all processed alarms
    severity_pattern = r"(^|-)(INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)(-|$)"
    match = re.search(severity_pattern, title)
    if not match:
        print(f"Alarm '{title}' contains no severity indicator - ignoring completely")
        return

    severity = match.group().strip('-')  # Extract matched severity level

    # Determine incident domain from alarm name patterns
    incident_domain = "APP"  # Default to application domain
    if "INFRA" in title:
        incident_domain = "INFRA"  # Infrastructure domain for INFRA-prefixed alarms

    # Build ASFF Resources array - always include origin account for cross-account tracking
    resources = [
        {
            "Type": "AwsAccountId",  # Required: identifies the account where alarm originated
            "Id": account_id,
            "Region": region,
        }
    ]
    
    # Attempt to extract monitored resource for enhanced SOAR processing
    monitored_resource = extract_monitored_resource(detail, account_id, region)
    if monitored_resource:
        resources.append(monitored_resource)  # Add as second resource
        print(f"Enhanced finding with monitored resource: {monitored_resource['Type']} - {monitored_resource['Id']}")
    else:
        print("No supported monitored resource found - using account-only resource (backward compatible)")

    # Create ASFF-compliant Security Hub finding
    finding = {
        # Required ASFF fields
        "SchemaVersion": "2018-10-08",  # ASFF version
        "Id": finding_id,  # Unique finding identifier (from event ID)
        "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": title,  # Alarm name as generator
        "AwsAccountId": account_id,  # Account where finding is published
        "Types": [
            f"Software and Configuration Checks/CloudWatch Alarms/{ALARM_TYPE}",
        ],
        "CreatedAt": alarm_timestamp,  # Actual alarm trigger time
        "UpdatedAt": alarm_timestamp,  # Same as created for new findings
        "FirstObservedAt": alarm_timestamp,  # When the alarm condition was first detected
        "LastObservedAt": alarm_timestamp,  # Same as first observed for new alarm states
        
        # Severity and description
        "Severity": {
            "Label": severity  # INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL
        },
        "Title": title,  # Alarm name as finding title
        "Description": description,  # Alarm description
        
        # Enhanced resource array (account + monitored resource if available)
        "Resources": resources,
        
        # SOAR-specific metadata for incident processing
        "ProductFields": {
            "aws/securityhub/FindingId": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default/{finding_id}",
            "aws/securityhub/ProductName": "Default",
            "aws/securityhub/CompanyName": COMPANY_NAME,
            "TicketDestination": "TEAM",  # Route to team for manual intervention
            "IncidentDomain": incident_domain  # INFRA or APP domain classification
        },
        
        # Security Hub workflow fields
        "VerificationState": "TRUE_POSITIVE",  # All alarms are valid incidents
        "Workflow": {
            "Status": "NEW"  # Start in NEW status for SOAR processing
        },
        "RecordState": "ACTIVE"  # Active finding for processing
    }

    # Publish finding to Security Hub via cross-account role assumption
    print(f"Publishing {severity} {incident_domain} finding for alarm '{title}'")
    
    try:
        # Get cross-account Security Hub client
        client = get_client('securityhub', account_id, region)
        
        # Publish finding to Security Hub
        response = client.batch_import_findings(Findings=[finding])
        
        # Check for publication errors
        if response['FailedCount'] != 0:
            print(f"Failed to import finding: {response['FailedFindings']}")
            return False  # Indicate failure for monitoring
        else:
            print(f"Successfully published finding {finding_id} to Security Hub")
            return True
            
    except Exception as e:
        print(f"Error publishing to Security Hub: {str(e)}")
        raise  # Re-raise for Lambda error handling


def extract_alarm_timestamp(event: Dict[str, Any]) -> str:
    """
    Extract the most accurate timestamp for the alarm state change.
    
    Priority:
    1. newState.timestamp - actual alarm trigger time
    2. previousState.timestamp - last known state change  
    3. event['time'] - EventBridge processing time (fallback)
    
    Args:
        event: CloudWatch alarm state change event
        
    Returns:
        ISO 8601 timestamp string
    """
    try:
        # Try to get the actual alarm state change timestamp
        new_state_timestamp = event.get('detail', {}).get('newState', {}).get('timestamp')
        if new_state_timestamp:
            # Convert CloudWatch timestamp format to ISO 8601
            # CloudWatch format: "2024-06-19T12:00:00.000+0000" 
            # Security Hub needs: "2024-06-19T12:00:00.000Z"
            if new_state_timestamp.endswith('+0000'):
                return new_state_timestamp.replace('+0000', 'Z')
            elif new_state_timestamp.endswith('.000Z'):
                return new_state_timestamp
            # If already in correct format, return as-is
            return new_state_timestamp
            
    except (KeyError, TypeError) as e:
        print(f"Could not extract newState.timestamp: {e}")
    
    try:
        # Fallback to previous state timestamp if available
        prev_state_timestamp = event.get('detail', {}).get('previousState', {}).get('timestamp')
        if prev_state_timestamp:
            if prev_state_timestamp.endswith('+0000'):
                return prev_state_timestamp.replace('+0000', 'Z')
            elif prev_state_timestamp.endswith('.000Z'):
                return prev_state_timestamp
            return prev_state_timestamp
            
    except (KeyError, TypeError) as e:
        print(f"Could not extract previousState.timestamp: {e}")
    
    # Final fallback to EventBridge event timestamp
    event_time = event.get('time', '')
    print(f"Using EventBridge timestamp as fallback: {event_time}")
    return event_time


def get_client(client_type, account_id, region, role='SecurityHubRole'):
    """Create AWS client with cross-account role assumption
    
    Assumes a role in the target account to access AWS services, enabling
    this Lambda (running in Security Hub admin account) to publish findings
    to Security Hub in the origin account.
    
    Args:
        client_type (str): AWS service name (e.g., 'securityhub')
        account_id (str): Target AWS account ID for role assumption
        region (str): AWS region for the client
        role (str, optional): IAM role name to assume. Defaults to 'SecurityHubRole'
        
    Returns:
        boto3.client: Configured AWS client with assumed role credentials
        
    Raises:
        botocore.exceptions.ClientError: If role assumption fails
    """
    # Assume cross-account role for service access
    role_arn = f"arn:aws:iam::{account_id}:role/{role}"
    session_name = f"cross_acct_lambda_session_{account_id}"
    
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )
    
    # Extract temporary credentials
    credentials = assumed_role['Credentials']
    
    # Create service client with assumed role credentials
    return boto3.client(
        client_type,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
