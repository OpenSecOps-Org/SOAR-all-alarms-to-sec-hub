"""
Pytest configuration and fixtures for SOAR All Alarms to Security Hub tests

This file provides shared test fixtures and configuration for the test suite,
following SOAR testing patterns and best practices.
"""

import pytest
import os
from unittest.mock import MagicMock

# Load environment from .env.test file automatically (following SOAR pattern)
try:
    from dotenv import load_dotenv
    load_dotenv('.env.test', override=True)
except ImportError:
    # python-dotenv not installed, skip automatic loading
    pass


@pytest.fixture(autouse=True)
def aws_credentials():
    """
    Mock AWS credentials for testing (auto-applied to all tests).
    
    This fixture sets up mock AWS credentials to prevent tests from
    accidentally using real AWS services or credentials.
    Following SOAR pattern with autouse=True.
    """
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
    
    # Set required lambda function environment variables
    os.environ['ALARM_TYPE'] = 'soar-cloudwatch-alarms-test'
    os.environ['COMPANY_NAME'] = 'Test Company SOAR'


@pytest.fixture
def mock_environment_variables():
    """
    Set up mock environment variables for testing.
    
    Provides the required environment variables that the lambda function
    expects, with safe test values.
    """
    test_env_vars = {
        'ALARM_TYPE': 'soar-cloudwatch-alarms-test',
        'COMPANY_NAME': 'Test Company SOAR'
    }
    
    # Apply test environment variables
    for key, value in test_env_vars.items():
        os.environ[key] = value
    
    yield test_env_vars
    
    # Cleanup environment variables after test
    for key in test_env_vars.keys():
        if key in os.environ:
            del os.environ[key]


@pytest.fixture
def sample_cloudwatch_alarm_event():
    """
    Provide a sample CloudWatch alarm state change event for testing.
    
    This represents the standard event structure that the lambda function
    receives from EventBridge when a CloudWatch alarm changes state.
    """
    return {
        "version": "0",
        "id": "01234567-0123-0123-0123-012345678901",
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": "123456789012",
        "time": "2024-06-19T12:00:00Z",
        "region": "us-east-1",
        "resources": [
            "arn:aws:cloudwatch:us-east-1:123456789012:alarm:INFRA-TestService-Failure-HIGH"
        ],
        "detail": {
            "alarmName": "INFRA-TestService-Failure-HIGH",
            "configuration": {
                "description": "Test service failure detection alarm",
                "metricName": "Errors",
                "namespace": "AWS/Lambda",
                "statistic": "Sum",
                "dimensions": [
                    {
                        "name": "FunctionName",
                        "value": "TestServiceFunction"
                    }
                ],
                "period": 60,
                "evaluationPeriods": 1,
                "threshold": 1.0,
                "comparisonOperator": "GreaterThanOrEqualToThreshold"
            },
            "newState": {
                "value": "ALARM",
                "reason": "Threshold Crossed: 1 out of the last 1 datapoints [2.0 (19/06/24 12:00:00)] was greater than or equal to the threshold (1.0) (minimum 1 datapoint for OK -> ALARM transition).",
                "timestamp": "2024-06-19T12:00:00.000+0000"
            },
            "previousState": {
                "value": "OK",
                "reason": "Threshold Crossed: no datapoints were received for 1 period and 1 missing datapoint was treated as [NonBreaching].",
                "timestamp": "2024-06-19T11:45:00.000+0000"
            }
        }
    }


@pytest.fixture
def sample_stepfunctions_alarm_event():
    """
    Provide a sample Step Functions alarm event for testing.
    
    This represents a CloudWatch alarm for Step Functions state machine failures.
    """
    return {
        "version": "0",
        "id": "sf-alarm-01234567-0123-0123-0123-012345678901",
        "detail-type": "CloudWatch Alarm State Change", 
        "source": "aws.cloudwatch",
        "account": "555666777888",
        "time": "2024-06-19T14:30:00Z",
        "region": "eu-west-1",
        "resources": [
            "arn:aws:cloudwatch:eu-west-1:555666777888:alarm:INFRA-ProcessorStateMachine-Failure-CRITICAL"
        ],
        "detail": {
            "alarmName": "INFRA-ProcessorStateMachine-Failure-CRITICAL",
            "configuration": {
                "description": "The ProcessorStateMachine state machine failed.",
                "metricName": "ExecutionsFailed",
                "namespace": "AWS/States",
                "statistic": "Sum", 
                "dimensions": [
                    {
                        "name": "StateMachineArn",
                        "value": "arn:aws:states:eu-west-1:555666777888:stateMachine:ProcessorStateMachine-ABC123"
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
                "reason": "Threshold Crossed: no datapoints were received for 1 period and 1 missing datapoint was treated as [NonBreaching].",
                "timestamp": "2024-06-19T14:15:00.000+0000"  
            }
        }
    }


@pytest.fixture
def mock_security_hub_client():
    """
    Provide a mock Security Hub client for testing.
    
    This fixture creates a properly configured mock that simulates
    successful Security Hub API responses.
    """
    mock_client = MagicMock()
    
    # Mock successful batch_import_findings response
    mock_client.batch_import_findings.return_value = {
        'FailedCount': 0,
        'SuccessCount': 1,
        'FailedFindings': []
    }
    
    return mock_client


@pytest.fixture
def mock_sts_client():
    """
    Provide a mock STS client for testing role assumption.
    
    This fixture creates a mock STS client that simulates successful
    cross-account role assumption.
    """
    mock_client = MagicMock()
    
    # Mock successful assume_role response
    mock_client.assume_role.return_value = {
        'Credentials': {
            'AccessKeyId': 'AKIATEST12345',
            'SecretAccessKey': 'test-secret-access-key',
            'SessionToken': 'test-session-token',
            'Expiration': '2024-06-19T16:00:00Z'
        },
        'AssumedRoleUser': {
            'AssumedRoleId': 'AROATEST12345:test-session',
            'Arn': 'arn:aws:sts::123456789012:assumed-role/SecurityHubRole/test-session'
        }
    }
    
    return mock_client