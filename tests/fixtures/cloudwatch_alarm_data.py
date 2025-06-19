"""
Centralized CloudWatch Alarm Event Test Data - Enhanced with Real Infrastructure Data

This module provides standardized CloudWatch alarm event fixtures for testing,
following the SOAR pattern of centralized test data management.

Enhanced with patterns from real AWS infrastructure while maintaining anonymization.
"""

from typing import Dict, Any, List, Optional


def create_cloudwatch_alarm_event(
    alarm_name: str,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    event_id: str = "test-event-123",
    description: str = "Test alarm description",
    namespace: str = "AWS/Lambda",
    dimensions: Optional[List[Dict[str, str]]] = None,
    new_state: str = "ALARM",
    previous_state: str = "OK"
) -> Dict[str, Any]:
    """
    Create a standardized CloudWatch alarm state change event for testing.
    
    Args:
        alarm_name: Name of the CloudWatch alarm
        account_id: AWS account ID where alarm originated  
        region: AWS region
        event_id: Unique event identifier
        description: Alarm description
        namespace: CloudWatch namespace (AWS/Lambda, AWS/States, etc.)
        dimensions: Alarm dimensions list
        new_state: New alarm state
        previous_state: Previous alarm state
    
    Returns:
        Complete CloudWatch alarm state change event
    """
    if dimensions is None:
        dimensions = [{"name": "FunctionName", "value": "TestFunction"}]
    
    return {
        "version": "0",
        "id": event_id,
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": account_id,
        "time": "2024-06-19T12:00:00Z",
        "region": region,
        "resources": [
            f"arn:aws:cloudwatch:{region}:{account_id}:alarm:{alarm_name}"
        ],
        "detail": {
            "alarmName": alarm_name,
            "configuration": {
                "description": description,
                "metricName": "Errors",
                "namespace": namespace,
                "statistic": "Sum",
                "dimensions": dimensions,
                "period": 60,
                "evaluationPeriods": 1,
                "threshold": 1.0,
                "comparisonOperator": "GreaterThanOrEqualToThreshold"
            },
            "newState": {
                "value": new_state,
                "reason": f"Threshold Crossed: 1 out of the last 1 datapoints [2.0 (19/06/24 12:00:00)] was greater than or equal to the threshold (1.0).",
                "timestamp": "2024-06-19T12:00:00.000+0000"
            },
            "previousState": {
                "value": previous_state,
                "reason": f"Threshold Crossed: no datapoints were received for 1 period.",
                "timestamp": "2024-06-19T11:45:00.000+0000"
            }
        }
    }


def create_stepfunctions_alarm_event(
    alarm_name: str = "INFRA-TestStateMachine-Failure-HIGH",
    account_id: str = "123456789012",
    region: str = "us-east-1",
    state_machine_arn: str = None
) -> Dict[str, Any]:
    """
    Create a Step Functions alarm event for testing.
    
    Args:
        alarm_name: CloudWatch alarm name
        account_id: AWS account ID
        region: AWS region
        state_machine_arn: State machine ARN (auto-generated if None)
    
    Returns:
        CloudWatch alarm event for Step Functions
    """
    if state_machine_arn is None:
        state_machine_arn = f"arn:aws:states:{region}:{account_id}:stateMachine:TestStateMachine-ABC123"
    
    return create_cloudwatch_alarm_event(
        alarm_name=alarm_name,
        account_id=account_id,
        region=region,
        event_id="sf-alarm-123",
        description="The TestStateMachine state machine failed.",
        namespace="AWS/States",
        dimensions=[
            {
                "name": "StateMachineArn",
                "value": state_machine_arn
            }
        ]
    )


def create_lambda_alarm_event(
    alarm_name: str = "INFRA-TestFunction-Error-MEDIUM",
    account_id: str = "555666777888", 
    region: str = "eu-west-1",
    function_name: str = "TestFunction"
) -> Dict[str, Any]:
    """
    Create a Lambda function alarm event for testing.
    
    Args:
        alarm_name: CloudWatch alarm name
        account_id: AWS account ID
        region: AWS region  
        function_name: Lambda function name
    
    Returns:
        CloudWatch alarm event for Lambda function
    """
    return create_cloudwatch_alarm_event(
        alarm_name=alarm_name,
        account_id=account_id,
        region=region,
        event_id="lambda-alarm-123",
        description="Lambda function errors detected",
        namespace="AWS/Lambda",
        dimensions=[
            {
                "name": "FunctionName",
                "value": function_name
            }
        ]
    )


def create_unsupported_service_alarm_event(
    alarm_name: str = "INFRA-Database-Connection-HIGH",
    account_id: str = "123456789012",
    region: str = "us-east-1"
) -> Dict[str, Any]:
    """
    Create an alarm event for an unsupported service (e.g., RDS).
    
    Args:
        alarm_name: CloudWatch alarm name
        account_id: AWS account ID
        region: AWS region
    
    Returns:
        CloudWatch alarm event for unsupported service
    """
    return create_cloudwatch_alarm_event(
        alarm_name=alarm_name,
        account_id=account_id,
        region=region,
        event_id="unsupported-alarm-123",
        description="Database connection errors",
        namespace="AWS/RDS",  # Not yet supported for resource extraction
        dimensions=[
            {
                "name": "DBInstanceIdentifier",
                "value": "my-database-instance"
            }
        ]
    )


# Pre-built test cases for common scenarios
COMMON_TEST_EVENTS = {
    "stepfunctions_high": create_stepfunctions_alarm_event(
        alarm_name="INFRA-ProcessorStateMachine-Failure-HIGH",
        account_id="555666777888",
        region="eu-west-1"
    ),
    
    "lambda_medium": create_lambda_alarm_event(
        alarm_name="INFRA-ProcessorFunction-Error-MEDIUM",
        account_id="555666777888",
        region="eu-west-1",
        function_name="INFRA-ProcessorFunction-XYZ789"
    ),
    
    "unsupported_service": create_unsupported_service_alarm_event(),
    
    "cis_alarm": create_cloudwatch_alarm_event(
        alarm_name="CIS-SecurityCheck-HIGH",
        description="CIS compliance check alarm"
    ),
    
    "no_severity": create_cloudwatch_alarm_event(
        alarm_name="SomeAlarmWithoutSeverity",
        description="Alarm without severity indicator"
    )
}


# Real infrastructure-based fixtures (anonymized)
REAL_INFRASTRUCTURE_FIXTURES = {
    "real_stepfunctions_alarm": {
        "version": "0",
        "id": "sf-real-alarm-123",
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": "123456789012",
        "time": "2024-06-19T14:30:00Z",
        "region": "eu-north-1",
        "resources": [
            "arn:aws:cloudwatch:eu-north-1:123456789012:alarm:INFRA-ProcessorStateMachine-Failure-HIGH"
        ],
        "detail": {
            "alarmName": "INFRA-TestService-Failure-MEDIUM",
            "configuration": {
                "description": "The state machine ConfigureSSOAccountPermissionsSM failed.",
                "metricName": "ExecutionsFailed",
                "namespace": "AWS/States",
                "statistic": "Sum",
                "dimensions": [
                    {
                        "name": "StateMachineArn",
                        "value": "arn:aws:states:eu-north-1:123456789012:stateMachine:ProcessorStateMachine-ABC123"
                    }
                ],
                "period": 60,
                "evaluationPeriods": 1,
                "threshold": 1.0,
                "comparisonOperator": "GreaterThanOrEqualToThreshold"
            },
            "newState": {
                "value": "ALARM",
                "reason": "Threshold Crossed: 1 out of the last 1 datapoints [3.0 (19/06/24 14:30:00)] was greater than or equal to the threshold (1.0).",
                "timestamp": "2024-06-19T14:30:00.000+0000"
            },
            "previousState": {
                "value": "OK",
                "reason": "Threshold Crossed: no datapoints were received for 1 period.",
                "timestamp": "2024-06-19T14:15:00.000+0000"
            }
        }
    },
    "real_lambda_alarm": {
        "version": "0",
        "id": "lambda-real-alarm-123",
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": "555666777888",
        "time": "2024-06-19T16:15:00Z",
        "region": "eu-north-1",
        "resources": [
            "arn:aws:cloudwatch:eu-north-1:555666777888:alarm:INFRA-ProcessorFunction-Error-MEDIUM"
        ],
        "detail": {
            "alarmName": "INFRA-TestService-Failure-HIGH",
            "configuration": {
                "description": "CreateDelegationTriggerFunction failed.",
                "metricName": "Errors",
                "namespace": "AWS/Lambda",
                "statistic": "Sum",
                "dimensions": [
                    {
                        "name": "FunctionName",
                        "value": "ProcessorFunction-XYZ789"
                    }
                ],
                "period": 60,
                "evaluationPeriods": 1,
                "threshold": 1.0,
                "comparisonOperator": "GreaterThanOrEqualToThreshold"
            },
            "newState": {
                "value": "ALARM",
                "reason": "Threshold Crossed: 2 out of the last 1 datapoints [2.0 (19/06/24 16:15:00)] was greater than or equal to the threshold (1.0).",
                "timestamp": "2024-06-19T16:15:00.000+0000"
            },
            "previousState": {
                "value": "OK",
                "reason": "Threshold Crossed: no datapoints were received for 1 period.",
                "timestamp": "2024-06-19T16:00:00.000+0000"
            }
        }
    },
    "real_complex_alarm": {
        "version": "0",
        "id": "complex-real-alarm-123",
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": "123456789012",
        "time": "2024-06-19T18:45:00Z",
        "region": "eu-north-1",
        "resources": [
            "arn:aws:cloudwatch:eu-north-1:123456789012:alarm:INFRA-MultiDimensionService-Critical-CRITICAL"
        ],
        "detail": {
            "alarmName": "INFRA-MultiDimensionService-Critical-CRITICAL",
            "configuration": {
                "description": "Multi-dimension service critical threshold",
                "metricName": "ErrorRate",
                "namespace": "AWS/ApplicationELB",
                "statistic": "Average",
                "dimensions": [
                    {
                        "name": "LoadBalancer",
                        "value": "app/test-alb/1234567890abcdef"
                    },
                    {
                        "name": "TargetGroup",
                        "value": "targetgroup/test-tg/abcdef1234567890"
                    }
                ],
                "period": 300,
                "evaluationPeriods": 2,
                "threshold": 5.0,
                "comparisonOperator": "GreaterThanThreshold"
            },
            "newState": {
                "value": "ALARM",
                "reason": "Threshold Crossed: 2 out of the last 2 datapoints [7.5 (19/06/24 18:45:00), 6.2 (19/06/24 18:40:00)] was greater than the threshold (5.0).",
                "timestamp": "2024-06-19T18:45:00.000+0000"
            },
            "previousState": {
                "value": "INSUFFICIENT_DATA",
                "reason": "Insufficient Data: 1 datapoint was unknown.",
                "timestamp": "2024-06-19T18:35:00.000+0000"
            }
        }
    },
    "real_security_hub_finding": {
        "SchemaVersion": "2018-10-08",
        "Id": "real-finding-123456",
        "ProductArn": "arn:aws:securityhub:eu-north-1:123456789012:product/123456789012/default",
        "GeneratorId": "INFRA-RealService-Error-HIGH",
        "AwsAccountId": "123456789012",
        "Types": [
            "Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms"
        ],
        "CreatedAt": "2024-06-19T15:30:00Z",
        "UpdatedAt": "2024-06-19T15:30:00Z",
        "Severity": {
            "Label": "HIGH"
        },
        "Title": "INFRA-RealService-Error-HIGH",
        "Description": "Real service error detection based on actual alarm",
        "Resources": [
            {
                "Type": "AwsAccountId",
                "Id": "123456789012",
                "Region": "eu-north-1"
            },
            {
                "Type": "AwsStatesStateMachine",
                "Id": "arn:aws:states:eu-north-1:123456789012:stateMachine:RealStateMachine-ABC123",
                "Region": "eu-north-1"
            }
        ],
        "ProductFields": {
            "aws/securityhub/FindingId": "arn:aws:securityhub:eu-north-1:123456789012:product/123456789012/default/real-finding-123456",
            "aws/securityhub/ProductName": "Default",
            "aws/securityhub/CompanyName": "OpenSecOps SOAR",
            "TicketDestination": "TEAM",
            "IncidentDomain": "INFRA"
        },
        "VerificationState": "TRUE_POSITIVE",
        "Workflow": {
            "Status": "NEW"
        },
        "RecordState": "ACTIVE"
    }
}
"""

Fixtures based on real AWS infrastructure patterns while maintaining data anonymization.
These provide more realistic test scenarios for comprehensive testing.
"""
