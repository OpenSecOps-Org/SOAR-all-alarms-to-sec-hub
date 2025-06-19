"""
CloudWatch Alarms to Security Hub Integration - Specification Tests

This test suite serves as both comprehensive tests AND executable specification
for the CloudWatch alarm-to-Security Hub integration in SOAR.

Follows SOAR testing patterns and standards established in SOAR/tests/README.md

=== FUNCTIONAL SPECIFICATION ===

The CloudWatch Alarms to Security Hub Function transforms CloudWatch alarm 
state change events into Security Hub findings by:

1. ALARM DETECTION: Processing CloudWatch Alarm State Change events 
2. SEVERITY EXTRACTION: Parsing alarm names for severity levels
3. ALARM FILTERING: Suppressing CIS alarms and non-severity alarms
4. RESOURCE EXTRACTION: Extracting monitored resources from alarm configuration
5. FINDING CREATION: Creating ASFF-compliant Security Hub findings
6. CROSS-ACCOUNT: Publishing findings to Security Hub across accounts

=== ALARM EVENT PROCESSING STRATEGY ===

Input: CloudWatch Alarm State Change Event
- event['detail']['alarmName'] -> Finding title and severity
- event['detail']['configuration']['description'] -> Finding description  
- event['detail']['configuration']['namespace'] -> AWS service (AWS/States, AWS/Lambda)
- event['detail']['configuration']['dimensions'] -> Monitored resource details
- event['account'] -> Origin account for cross-account tracking
- event['region'] -> AWS region for resource placement

Output: Security Hub Finding (ASFF)
- Resources: Both origin account AND monitored resource
- Severity: Extracted from alarm name (LOW, MEDIUM, HIGH, CRITICAL)
- Types: CloudWatch alarm classification
- ProductFields: SOAR-specific metadata

=== MONITORED RESOURCE EXTRACTION ===

Step Functions (AWS/States):
- Namespace: "AWS/States"
- Dimension: StateMachineArn -> Resource Type: AwsStatesStateMachine
- Direct ARN extraction from dimension value

Lambda Functions (AWS/Lambda):  
- Namespace: "AWS/Lambda"
- Dimension: FunctionName -> Resource Type: AwsLambdaFunction
- ARN construction: arn:aws:lambda:{region}:{account}:function:{function_name}

Other Services:
- Include only origin account resource
- Future extensibility for additional services

=== SECURITY HUB FINDING STRUCTURE ===

Required ASFF Fields:
- SchemaVersion: "2018-10-08" 
- Id: Event ID from CloudWatch alarm event
- ProductArn: Security Hub product ARN
- GeneratorId: Alarm name
- AwsAccountId: Origin account ID
- Types: CloudWatch alarm type classification
- CreatedAt/UpdatedAt: Event timestamp
- Severity: Parsed from alarm name
- Title: Alarm name
- Description: Alarm description
- Resources: Origin account + monitored resource (if supported)
- ProductFields: SOAR metadata (IncidentDomain, TicketDestination)

=== ERROR HANDLING REQUIREMENTS ===

The function MUST:
- Suppress alarms without severity indicators
- Suppress CIS alarms explicitly  
- Handle malformed alarm configurations gracefully
- Continue processing when monitored resource extraction fails
- Provide meaningful error logging
- Never crash on unexpected input

=== CROSS-ACCOUNT OPERATION ===

The function operates in Security Hub admin account but processes events from:
- All organization accounts via EventBridge custom bus
- Cross-account role assumption for Security Hub publishing
- Account ID tracking in Resources for origin identification

=== TEST ORGANIZATION ===

Tests are organized as an executable specification following TDD principles:
1. Basic function contract and entry points
2. CloudWatch alarm event detection and filtering  
3. Severity extraction and alarm name parsing
4. Monitored resource extraction from alarm configuration
5. Security Hub finding creation and ASFF compliance
6. Cross-account operations and role assumption
7. Error handling and edge cases
8. Integration testing with real AWS services
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, call
from datetime import datetime
import json
import botocore.exceptions
import importlib.util

# Add the lambda function to the Python path (following SOAR pattern)
lambda_path = os.path.join(os.path.dirname(__file__), '..', '..', 'lambda_function')
sys.path.insert(0, lambda_path)

# Import lambda app module using importlib to avoid keyword conflict
lambda_app_path = os.path.join(lambda_path, 'lambda', 'app.py')
spec = importlib.util.spec_from_file_location("lambda_app", lambda_app_path)
lambda_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lambda_app)

# Import centralized test data (following SOAR pattern)
from tests.fixtures.cloudwatch_alarm_data import (
    create_cloudwatch_alarm_event,
    create_stepfunctions_alarm_event, 
    create_lambda_alarm_event,
    create_unsupported_service_alarm_event,
    COMMON_TEST_EVENTS
)


class TestSpecification_1_BasicFunctionality:
    """
    SPECIFICATION 1: Basic Function Contract
    
    The lambda_handler function MUST:
    - Accept CloudWatch alarm state change events
    - Return success/failure indicators
    - Be callable without errors
    - Handle the standard AWS Lambda function signature
    """
    
    def test_lambda_handler_exists_and_callable(self):
        """REQUIREMENT: lambda_handler function must exist and be callable"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Verify function exists and is callable
        assert callable(lambda_handler)
        
        # Test with minimal event using centralized test data
        minimal_event = create_cloudwatch_alarm_event(
            alarm_name="TEST-ALARM-HIGH",
            event_id="test-id",
            description="Test alarm description"
        )
        
        # Should return without error (we'll mock AWS calls later)
        with patch.object(lambda_app, 'get_client'):
            result = lambda_handler(minimal_event, None)
            assert result is True

    def test_function_has_required_imports(self):
        """REQUIREMENT: Function must import required AWS and system modules"""
        # Use already imported module to avoid keyword conflict
        # lambda_app is imported at module level
        
        # Verify key functions are available
        assert hasattr(lambda_app, 'lambda_handler')
        assert hasattr(lambda_app, 'get_client')


class TestSpecification_2_AlarmEventDetectionAndFiltering:
    """
    SPECIFICATION 2: CloudWatch Alarm Event Detection and Filtering
    
    The function MUST correctly process CloudWatch alarm events:
    - Process valid alarm state change events
    - Extract required fields from event structure
    - Apply filtering rules (CIS suppression, severity requirements)
    - Handle malformed events gracefully
    """
    
    def test_extracts_basic_event_fields(self):
        """REQUIREMENT: Must extract core fields from CloudWatch alarm event"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data
        test_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-TestService-Failure-HIGH",
            account_id="555666777888",
            region="eu-west-1",
            event_id="alarm-event-123",
            description="Test service alarm description"
        )
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(test_event, None)
            
            # Should successfully process the event
            assert result is True
            
            # Verify Security Hub was called with extracted fields
            mock_securityhub.batch_import_findings.assert_called_once()
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            # Verify basic field extraction
            assert finding['Id'] == "alarm-event-123"
            assert finding['AwsAccountId'] == "555666777888"
            assert finding['Title'] == "INFRA-TestService-Failure-HIGH"
            assert finding['Description'] == "Test service alarm description"

    def test_suppresses_cis_alarms(self):
        """REQUIREMENT: Must suppress CIS alarms completely"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use pre-built test event
        cis_alarm_event = COMMON_TEST_EVENTS["cis_alarm"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            result = lambda_handler(cis_alarm_event, None)
            
            # Should return early without processing
            assert result is None
            
            # Should not call AWS services at all
            mock_get_client.assert_not_called()

    def test_suppresses_alarms_without_severity(self):
        """REQUIREMENT: Must suppress alarms that don't contain severity levels"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use pre-built test event
        no_severity_event = COMMON_TEST_EVENTS["no_severity"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            result = lambda_handler(no_severity_event, None)
            
            # Should return early without processing  
            assert result is None
            
            # Should not call AWS services
            mock_get_client.assert_not_called()


class TestSpecification_3_SeverityExtractionAndAlarmNameParsing:
    """
    SPECIFICATION 3: Severity Extraction and Alarm Name Parsing
    
    The function MUST correctly extract severity from alarm names:
    - Recognize standard severity levels: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    - Handle severity indicators at different positions in alarm name
    - Map severity to appropriate ASFF severity structure
    - Determine incident domain from alarm name patterns
    """
    
    def test_extracts_severity_levels(self):
        """REQUIREMENT: Must extract all standard severity levels from alarm names"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        severity_test_cases = [
            ("INFRA-Service-INFORMATIONAL", "INFORMATIONAL"),
            ("APP-Component-LOW", "LOW"), 
            ("INFRA-Database-MEDIUM", "MEDIUM"),
            ("CRITICAL-SystemFailure", "CRITICAL"),
            ("Service-HIGH-Alert", "HIGH")
        ]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            for alarm_name, expected_severity in severity_test_cases:
                # Use centralized test data creation
                test_event = create_cloudwatch_alarm_event(
                    alarm_name=alarm_name,
                    event_id=f"test-{expected_severity.lower()}",
                    description=f"Test {expected_severity} alarm"
                )
                
                result = lambda_handler(test_event, None)
                assert result is True
                
                # Verify severity was extracted correctly
                call_args = mock_securityhub.batch_import_findings.call_args[1]
                finding = call_args['Findings'][0]
                assert finding['Severity']['Label'] == expected_severity

    def test_determines_incident_domain_from_alarm_name(self):
        """REQUIREMENT: Must determine incident domain (INFRA vs APP) from alarm name"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        domain_test_cases = [
            ("INFRA-Database-Failure-HIGH", "INFRA"),
            ("APP-UserService-Error-MEDIUM", "APP"),
            ("Service-Without-Domain-LOW", "APP")  # Default to APP
        ]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            for alarm_name, expected_domain in domain_test_cases:
                # Use centralized test data creation
                test_event = create_cloudwatch_alarm_event(
                    alarm_name=alarm_name,
                    event_id=f"test-domain-{expected_domain.lower()}",
                    description="Test domain detection"
                )
                
                result = lambda_handler(test_event, None)
                assert result is True
                
                # Verify incident domain was determined correctly
                call_args = mock_securityhub.batch_import_findings.call_args[1]
                finding = call_args['Findings'][0]
                assert finding['ProductFields']['IncidentDomain'] == expected_domain


class TestSpecification_4_MonitoredResourceExtraction:
    """
    SPECIFICATION 4: Monitored Resource Extraction from Alarm Configuration
    
    The function MUST extract monitored resource information from alarm configuration:
    - Extract Step Functions state machine ARNs from AWS/States namespace
    - Extract Lambda function names and construct ARNs for AWS/Lambda namespace  
    - Handle unsupported services gracefully
    - Add monitored resources to ASFF Resources array alongside origin account
    """
    
    def test_extracts_stepfunctions_resources(self):
        """REQUIREMENT: Must extract Step Functions state machine resources from alarm config"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data with Step Functions configuration
        state_machine_arn = "arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine-ABC123"
        stepfunctions_event = create_stepfunctions_alarm_event(
            alarm_name="INFRA-MyStateMachine-Failure-HIGH",
            account_id="123456789012",
            region="us-east-1",
            state_machine_arn=state_machine_arn
        )
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(stepfunctions_event, None)
            assert result is True
            
            # Verify finding contains both origin account and monitored resource
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            resources = finding['Resources']
            
            # Should have 2 resources: origin account + monitored state machine
            assert len(resources) == 2
            
            # Origin account resource
            origin_resource = next(r for r in resources if r['Type'] == 'AwsAccountId')
            assert origin_resource['Id'] == "123456789012"
            assert origin_resource['Region'] == "us-east-1"
            
            # Monitored state machine resource
            sm_resource = next(r for r in resources if r['Type'] == 'AwsStatesStateMachine') 
            assert sm_resource['Id'] == state_machine_arn
            assert sm_resource['Region'] == "us-east-1"

    def test_extracts_lambda_resources(self):
        """REQUIREMENT: Must extract Lambda function resources and construct proper ARNs"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data for Lambda function alarm
        function_name = "INFRA-ProcessorFunction-XYZ789"
        lambda_event = create_lambda_alarm_event(
            alarm_name="INFRA-ProcessorFunction-Error-MEDIUM",
            account_id="555666777888",
            region="eu-west-1",
            function_name=function_name
        )
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(lambda_event, None)
            assert result is True
            
            # Verify finding contains both origin account and monitored resource
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            resources = finding['Resources']
            
            # Should have 2 resources: origin account + monitored Lambda function
            assert len(resources) == 2
            
            # Origin account resource  
            origin_resource = next(r for r in resources if r['Type'] == 'AwsAccountId')
            assert origin_resource['Id'] == "555666777888"
            assert origin_resource['Region'] == "eu-west-1"
            
            # Monitored Lambda function resource (ARN constructed)
            lambda_resource = next(r for r in resources if r['Type'] == 'AwsLambdaFunction')
            expected_arn = f"arn:aws:lambda:eu-west-1:555666777888:function:{function_name}"
            assert lambda_resource['Id'] == expected_arn
            assert lambda_resource['Region'] == "eu-west-1"

    def test_handles_unsupported_services_gracefully(self):
        """REQUIREMENT: Must handle unsupported services by including only origin account"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use pre-built test event for unsupported service
        unsupported_event = COMMON_TEST_EVENTS["unsupported_service"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(unsupported_event, None)
            assert result is True
            
            # Verify finding contains only origin account resource
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            resources = finding['Resources']
            
            # Should have only 1 resource: origin account
            assert len(resources) == 1
            
            # Origin account resource
            origin_resource = resources[0]
            assert origin_resource['Type'] == 'AwsAccountId'
            assert origin_resource['Id'] == "123456789012"
            assert origin_resource['Region'] == "us-east-1"

    def test_handles_missing_alarm_configuration_gracefully(self):
        """REQUIREMENT: Must handle missing or malformed alarm configuration"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Create malformed event with missing namespace and dimensions
        malformed_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-Service-Error-HIGH",
            event_id="malformed-alarm-123",
            description="Service with missing namespace"
        )
        # Remove namespace and dimensions to simulate malformed configuration
        del malformed_event['detail']['configuration']['namespace']
        del malformed_event['detail']['configuration']['dimensions']
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(malformed_event, None)
            assert result is True
            
            # Should still create finding with origin account resource
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            resources = finding['Resources']
            
            # Should have only origin account resource
            assert len(resources) == 1
            assert resources[0]['Type'] == 'AwsAccountId'


class TestSpecification_5_SecurityHubFindingCreationAndASFFCompliance:
    """
    SPECIFICATION 5: Security Hub Finding Creation and ASFF Compliance
    
    The function MUST create valid ASFF-compliant Security Hub findings:
    - Include all required ASFF fields with correct data types
    - Use proper Security Hub product ARN format
    - Set appropriate finding types for CloudWatch alarms
    - Include SOAR-specific metadata in ProductFields
    - Handle timestamps in ISO 8601 format
    """
    
    def test_creates_asff_compliant_finding_structure(self):
        """REQUIREMENT: Must create findings that comply with ASFF schema"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data with specific timestamp
        complete_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-TestService-Failure-HIGH",
            event_id="complete-test-123",
            description="Test service failure detection"
        )
        # Override timestamp for specific test
        complete_event['time'] = "2024-06-19T15:30:45Z"
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(complete_event, None)
            assert result is True
            
            # Verify ASFF compliance
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            # Required ASFF fields
            assert finding['SchemaVersion'] == "2018-10-08"
            assert finding['Id'] == "complete-test-123"
            assert 'ProductArn' in finding
            assert finding['ProductArn'].startswith('arn:aws:securityhub:')
            assert finding['GeneratorId'] == "INFRA-TestService-Failure-HIGH"
            assert finding['AwsAccountId'] == "123456789012"
            assert 'Types' in finding
            assert isinstance(finding['Types'], list)
            assert finding['CreatedAt'] == "2024-06-19T15:30:45Z"
            assert finding['UpdatedAt'] == "2024-06-19T15:30:45Z"
            assert 'Severity' in finding
            assert finding['Severity']['Label'] == "HIGH"
            assert finding['Title'] == "INFRA-TestService-Failure-HIGH"
            assert finding['Description'] == "Test service failure detection"
            assert 'Resources' in finding
            assert isinstance(finding['Resources'], list)
            assert len(finding['Resources']) >= 1
            
            # SOAR-specific metadata
            assert 'ProductFields' in finding
            assert 'IncidentDomain' in finding['ProductFields']
            assert 'TicketDestination' in finding['ProductFields']
            assert finding['ProductFields']['TicketDestination'] == "TEAM"
            
            # Security Hub metadata
            assert 'VerificationState' in finding
            assert 'Workflow' in finding
            assert 'RecordState' in finding

    def test_sets_correct_finding_types_for_cloudwatch_alarms(self):
        """REQUIREMENT: Must set appropriate Types field for CloudWatch alarm findings"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data
        test_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-Service-Alert-MEDIUM",
            event_id="types-test-123",
            description="Service alert"
        )
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            # Mock module variable for alarm type (since module loads env vars at import time)
            with patch.object(lambda_app, 'ALARM_TYPE', 'soar-cloudwatch-alarms'):
                result = lambda_handler(test_event, None)
                assert result is True
                
                # Verify finding types
                call_args = mock_securityhub.batch_import_findings.call_args[1]
                finding = call_args['Findings'][0]
                
                expected_types = ["Software and Configuration Checks/CloudWatch Alarms/soar-cloudwatch-alarms"]
                assert finding['Types'] == expected_types


class TestSpecification_6_CrossAccountOperationsAndRoleAssumption:
    """
    SPECIFICATION 6: Cross-Account Operations and Role Assumption
    
    The function MUST handle cross-account operations correctly:
    - Assume cross-account role for Security Hub access
    - Generate proper session names for role assumption
    - Handle role assumption failures gracefully
    - Publish findings to correct account's Security Hub
    """
    
    def test_assumes_cross_account_role_for_security_hub_access(self):
        """REQUIREMENT: Must assume cross-account role to access Security Hub"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data for cross-account scenario
        cross_account_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-Service-Error-HIGH",
            account_id="999888777666",  # Different account
            region="eu-west-1",
            event_id="cross-account-123",
            description="Cross-account service error"
        )
        
        with patch.object(lambda_app, 'sts_client') as mock_sts:
            # Mock successful role assumption
            mock_sts.assume_role.return_value = {
                'Credentials': {
                    'AccessKeyId': 'AKIA...',
                    'SecretAccessKey': 'secret...',
                    'SessionToken': 'token...'
                }
            }
            
            with patch('boto3.client') as mock_boto3_client:
                mock_securityhub = MagicMock()
                mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
                mock_boto3_client.return_value = mock_securityhub
                
                result = lambda_handler(cross_account_event, None)
                assert result is True
                
                # Verify cross-account role assumption
                expected_role_arn = "arn:aws:iam::999888777666:role/SecurityHubRole"
                expected_session_name = "cross_acct_lambda_session_999888777666"
                
                mock_sts.assume_role.assert_called_once_with(
                    RoleArn=expected_role_arn,
                    RoleSessionName=expected_session_name
                )
                
                # Verify Security Hub client created with assumed credentials
                mock_boto3_client.assert_called_once()
                call_args = mock_boto3_client.call_args
                assert call_args[0][0] == 'securityhub'  # Service name
                assert 'aws_access_key_id' in call_args[1]
                assert 'aws_secret_access_key' in call_args[1] 
                assert 'aws_session_token' in call_args[1]
                assert call_args[1]['region_name'] == 'eu-west-1'

    def test_handles_role_assumption_failure_gracefully(self):
        """REQUIREMENT: Must handle role assumption failures without crashing"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data for role failure scenario
        test_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-Service-Error-HIGH",
            event_id="role-failure-123",
            description="Test role failure handling"
        )
        
        with patch.object(lambda_app, 'sts_client') as mock_sts:
            # Mock role assumption failure
            mock_sts.assume_role.side_effect = botocore.exceptions.ClientError(
                error_response={'Error': {'Code': 'AccessDenied', 'Message': 'Role assumption denied'}},
                operation_name='AssumeRole'
            )
            
            # Function should handle the error gracefully
            # Depending on implementation, might return False or re-raise
            try:
                result = lambda_handler(test_event, None)
                # If it returns, it should be False or handle the error
                assert result is not True
            except Exception as e:
                # If it raises, should be a meaningful error
                assert "Role assumption" in str(e) or "AccessDenied" in str(e)


class TestSpecification_7_ErrorHandlingAndEdgeCases:
    """
    SPECIFICATION 7: Error Handling and Edge Cases
    
    The function MUST handle various error conditions gracefully:
    - Malformed event structures
    - Missing required fields
    - Security Hub API failures
    - Network timeouts and retries
    - Unexpected data types and values
    """
    
    def test_handles_missing_event_fields_gracefully(self):
        """REQUIREMENT: Must handle events with missing required fields"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Create incomplete events using base structure
        base_event = create_cloudwatch_alarm_event("TEST-ALARM-HIGH")
        
        incomplete_events = [
            # Missing detail section
            {
                "id": "missing-detail",
                "account": "123456789012",
                "region": "us-east-1",
                "time": "2024-06-19T10:30:00Z"
            },
            # Missing alarm name
            {
                **base_event,
                "id": "missing-alarm-name",
                "detail": {
                    "configuration": {
                        "description": "Missing alarm name"
                    }
                }
            },
            # Missing account
            {
                **{k: v for k, v in base_event.items() if k != 'account'},
                "id": "missing-account"
            }
        ]
        
        for incomplete_event in incomplete_events:
            # Should not crash on malformed events
            try:
                result = lambda_handler(incomplete_event, None)
                # Should return early or handle gracefully
                assert result is not True or result is None
            except KeyError as e:
                # If it raises KeyError, should be for a critical field
                assert str(e) in ["'detail'", "'alarmName'", "'account'", "'region'"]
            except Exception as e:
                # Any other exception should be handled gracefully
                assert False, f"Unexpected exception for incomplete event: {e}"

    def test_handles_security_hub_api_failures(self):
        """REQUIREMENT: Must handle Security Hub API failures appropriately"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Use centralized test data
        test_event = create_cloudwatch_alarm_event(
            alarm_name="INFRA-Service-Error-HIGH",
            event_id="api-failure-test",
            description="Test API failure handling"
        )
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            
            # Test different API failure scenarios
            api_failures = [
                # Failed findings import
                {'FailedCount': 1, 'FailedFindings': [{'Id': 'test', 'ErrorCode': 'InvalidInput'}]},
                # Network error
                botocore.exceptions.ClientError(
                    error_response={'Error': {'Code': 'NetworkError', 'Message': 'Network timeout'}},
                    operation_name='BatchImportFindings'
                )
            ]
            
            for failure in api_failures:
                if isinstance(failure, dict):
                    mock_securityhub.batch_import_findings.return_value = failure
                else:
                    mock_securityhub.batch_import_findings.side_effect = failure
                
                mock_get_client.return_value = mock_securityhub
                
                # Should handle the failure gracefully
                try:
                    result = lambda_handler(test_event, None)
                    # Depending on implementation, might return False or True
                    assert result is not None
                except Exception as e:
                    # Should handle API errors gracefully
                    assert "NetworkError" in str(e) or "Failed to import" in str(e)

    def test_handles_unexpected_data_types(self):
        """REQUIREMENT: Must handle unexpected data types in event fields"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Create malformed event with wrong data types
        malformed_event = {
            "id": 12345,  # Should be string
            "account": "123456789012",
            "region": "us-east-1", 
            "time": "2024-06-19T10:30:00Z",
            "detail": {
                "alarmName": ["INFRA", "Service", "HIGH"],  # Should be string
                "configuration": {
                    "description": None  # Should be string
                }
            }
        }
        
        # Should handle type conversion or validation gracefully
        try:
            with patch.object(lambda_app, 'get_client'):
                result = lambda_handler(malformed_event, None)
                # Should either process successfully after type conversion
                # or fail gracefully with appropriate error handling
                assert result is not None
        except (TypeError, ValueError) as e:
            # Acceptable to raise type/value errors for invalid data
            assert "string" in str(e).lower() or "type" in str(e).lower()

    def test_resource_extraction_handles_malformed_dimensions(self):
        """REQUIREMENT: Must handle malformed dimensions data gracefully"""
        # Use imported module to avoid keyword conflict
        lambda_handler = lambda_app.lambda_handler
        
        # Test various malformed dimension scenarios
        malformed_events = [
            # dimensions is not a list
            create_cloudwatch_alarm_event("INFRA-Test-HIGH", "malformed-dims-1", "Test"),
            # dimensions contains non-dict items
            create_cloudwatch_alarm_event("INFRA-Test-HIGH", "malformed-dims-2", "Test"),
            # dimension values are not strings
            create_cloudwatch_alarm_event("INFRA-Test-HIGH", "malformed-dims-3", "Test"),
        ]
        
        # Modify the events to have malformed dimensions
        malformed_events[0]['detail']['configuration']['dimensions'] = "not-a-list"
        malformed_events[1]['detail']['configuration']['dimensions'] = ["not-a-dict", 123]
        malformed_events[2]['detail']['configuration']['dimensions'] = [
            {"name": "StateMachineArn", "value": 12345}  # Value should be string
        ]
        malformed_events[2]['detail']['configuration']['namespace'] = "AWS/States"
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            for event in malformed_events:
                # Should not crash on malformed dimensions
                result = lambda_handler(event, None)
                assert result is True
                
                # Should still create finding with only account resource
                call_args = mock_securityhub.batch_import_findings.call_args[1]
                finding = call_args['Findings'][0]
                resources = finding['Resources']
                
                # Should only have account resource (resource extraction should fail gracefully)
                assert len(resources) == 1
                assert resources[0]['Type'] == 'AwsAccountId'


class TestSpecification_8_IntegrationTestingWithRealAWSServices:
    """
    SPECIFICATION 8: Integration Testing with Real AWS Services
    
    These tests verify integration with actual AWS services:
    - End-to-end processing with real alarm events
    - Security Hub finding import validation
    - Cross-account role assumption testing
    - Performance and timeout handling
    
    Note: These tests require AWS credentials and may incur costs
    """
    
    @pytest.mark.integration
    def test_end_to_end_stepfunctions_alarm_processing(self):
        """INTEGRATION: End-to-end processing of Step Functions alarm event"""
        # This test would require real AWS credentials and services
        # Skipped in unit test environment
        pytest.skip("Integration test requires real AWS environment")
    
    @pytest.mark.integration 
    def test_end_to_end_lambda_alarm_processing(self):
        """INTEGRATION: End-to-end processing of Lambda function alarm event"""
        # This test would require real AWS credentials and services
        # Skipped in unit test environment
        pytest.skip("Integration test requires real AWS environment")
    
    @pytest.mark.integration
    def test_real_cross_account_role_assumption(self):
        """INTEGRATION: Real cross-account role assumption testing"""
        # This test would require multiple AWS accounts and roles
        # Skipped in unit test environment
        pytest.skip("Integration test requires multi-account AWS setup")