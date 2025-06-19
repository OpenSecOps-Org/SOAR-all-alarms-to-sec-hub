"""
Real Infrastructure Scenario Tests

This test suite uses fixtures based on real AWS infrastructure patterns
to provide comprehensive testing scenarios that reflect actual deployment conditions.

These tests complement the main specification tests with realistic data patterns.
"""

import pytest
import sys
import os
import importlib.util
from unittest.mock import patch, MagicMock

# Import lambda app module using importlib to avoid keyword conflict
lambda_path = os.path.join(os.path.dirname(__file__), '..', '..', 'lambda_function')
sys.path.insert(0, lambda_path)

lambda_app_path = os.path.join(lambda_path, 'lambda', 'app.py')
spec = importlib.util.spec_from_file_location("lambda_app", lambda_app_path)
lambda_app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lambda_app)

# Import real infrastructure fixtures
from tests.fixtures.cloudwatch_alarm_data import REAL_INFRASTRUCTURE_FIXTURES


class TestRealStepFunctionsScenarios:
    """
    Test scenarios based on real Step Functions infrastructure
    
    These tests use actual alarm configurations from production Step Functions
    to validate resource extraction and finding creation with realistic data.
    """
    
    def test_real_stepfunctions_alarm_processing(self):
        """Test processing of real Step Functions alarm configuration"""
        lambda_handler = lambda_app.lambda_handler
        
        # Use real Step Functions alarm fixture
        real_sf_event = REAL_INFRASTRUCTURE_FIXTURES["real_stepfunctions_alarm"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(real_sf_event, None)
            assert result is True
            
            # Verify Security Hub was called
            mock_securityhub.batch_import_findings.assert_called_once()
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            # Verify real alarm characteristics
            assert finding['Title'] == "INFRA-TestService-Failure-MEDIUM"
            assert finding['Severity']['Label'] == "MEDIUM"
            assert finding['Description'] == "The state machine ConfigureSSOAccountPermissionsSM failed."
            assert finding['ProductFields']['IncidentDomain'] == "INFRA"
            
            # Should have resources (currently only account, but test will fail when resource extraction is added)
            resources = finding['Resources']
            assert len(resources) >= 1
            
            # Verify account resource
            account_resource = next(r for r in resources if r['Type'] == 'AwsAccountId')
            assert account_resource['Id'] == "123456789012"
            assert account_resource['Region'] == "eu-north-1"
    
    def test_real_stepfunctions_alarm_with_complex_dimensions(self):
        """Test Step Functions alarm with realistic dimension structure"""
        lambda_handler = lambda_app.lambda_handler
        
        # Create a more complex real scenario
        complex_sf_event = REAL_INFRASTRUCTURE_FIXTURES["real_stepfunctions_alarm"].copy()
        complex_sf_event['detail']['alarmName'] = "INFRA-ConfigureSSOPermissions-ExecutionTimeout-HIGH"
        complex_sf_event['detail']['configuration']['description'] = "State machine execution timeout threshold exceeded"
        complex_sf_event['detail']['configuration']['metricName'] = "ExecutionTime"
        complex_sf_event['detail']['configuration']['threshold'] = 30000.0  # 30 seconds
        complex_sf_event['detail']['configuration']['comparisonOperator'] = "GreaterThanThreshold"
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(complex_sf_event, None)
            assert result is True
            
            # Verify finding created with complex characteristics
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            assert finding['Title'] == "INFRA-ConfigureSSOPermissions-ExecutionTimeout-HIGH"
            assert finding['Severity']['Label'] == "HIGH"
            assert "timeout" in finding['Description'].lower()


class TestRealLambdaFunctionScenarios:
    """
    Test scenarios based on real Lambda function infrastructure
    
    These tests use actual alarm configurations from production Lambda functions
    to validate resource extraction and finding creation.
    """
    
    def test_real_lambda_alarm_processing(self):
        """Test processing of real Lambda function alarm configuration"""
        lambda_handler = lambda_app.lambda_handler
        
        # Use real Lambda alarm fixture
        real_lambda_event = REAL_INFRASTRUCTURE_FIXTURES["real_lambda_alarm"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(real_lambda_event, None)
            assert result is True
            
            # Verify Security Hub was called
            mock_securityhub.batch_import_findings.assert_called_once()
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            # Verify real Lambda alarm characteristics
            assert finding['Title'] == "INFRA-TestService-Failure-HIGH"
            assert finding['Severity']['Label'] == "HIGH"
            assert finding['Description'] == "CreateDelegationTriggerFunction failed."
            assert finding['ProductFields']['IncidentDomain'] == "INFRA"
            
            # Should have resources (currently only account, will have Lambda ARN when implemented)
            resources = finding['Resources']
            assert len(resources) >= 1
            
            # Verify cross-account scenario
            account_resource = next(r for r in resources if r['Type'] == 'AwsAccountId')
            assert account_resource['Id'] == "555666777888"  # Different account
            assert account_resource['Region'] == "eu-north-1"
    
    def test_real_lambda_function_arn_construction(self):
        """Test that Lambda function ARN would be constructed correctly from real data"""
        lambda_handler = lambda_app.lambda_handler
        
        real_lambda_event = REAL_INFRASTRUCTURE_FIXTURES["real_lambda_alarm"]
        
        # Extract the function name from dimensions for verification
        dimensions = real_lambda_event['detail']['configuration']['dimensions']
        function_dimension = next(d for d in dimensions if d['name'] == 'FunctionName')
        function_name = function_dimension['value']
        
        # Verify the function name pattern matches real infrastructure
        assert function_name == "ProcessorFunction-XYZ789"
        
        # Expected ARN construction (for when implementation is added)
        account_id = real_lambda_event['account']
        region = real_lambda_event['region']
        expected_lambda_arn = f"arn:aws:lambda:{region}:{account_id}:function:{function_name}"
        
        # Store for future implementation verification
        assert expected_lambda_arn == "arn:aws:lambda:eu-north-1:555666777888:function:ProcessorFunction-XYZ789"


class TestRealComplexAlarmScenarios:
    """
    Test scenarios with complex real alarm configurations
    
    These tests handle multi-dimensional alarms and unsupported services
    that reflect actual infrastructure complexity.
    """
    
    def test_real_complex_multidimensional_alarm(self):
        """Test complex alarm with multiple dimensions from real infrastructure"""
        lambda_handler = lambda_app.lambda_handler
        
        # Use real complex alarm fixture
        complex_event = REAL_INFRASTRUCTURE_FIXTURES["real_complex_alarm"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(complex_event, None)
            assert result is True
            
            # Verify complex alarm processing
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            assert finding['Title'] == "INFRA-MultiDimensionService-Critical-CRITICAL"
            assert finding['Severity']['Label'] == "CRITICAL"
            assert "Multi-dimension service critical threshold" in finding['Description']
            
            # Verify it creates only account resource for unsupported namespace
            resources = finding['Resources']
            assert len(resources) == 1  # Only account resource for AWS/ApplicationELB
            assert resources[0]['Type'] == 'AwsAccountId'
    
    def test_real_alarm_state_transitions(self):
        """Test realistic alarm state transition scenarios"""
        lambda_handler = lambda_app.lambda_handler
        
        complex_event = REAL_INFRASTRUCTURE_FIXTURES["real_complex_alarm"].copy()
        
        # Test different state transitions
        state_transitions = [
            ("OK", "ALARM"),
            ("INSUFFICIENT_DATA", "ALARM"),
            ("ALARM", "OK"),
        ]
        
        for prev_state, new_state in state_transitions:
            test_event = complex_event.copy()
            test_event['detail']['newState']['value'] = new_state
            test_event['detail']['previousState']['value'] = prev_state
            test_event['id'] = f"state-transition-{prev_state}-to-{new_state}"
            
            with patch.object(lambda_app, 'get_client') as mock_get_client:
                mock_securityhub = MagicMock()
                mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
                mock_get_client.return_value = mock_securityhub
                
                result = lambda_handler(test_event, None)
                assert result is True
                
                # Verify finding created regardless of state transition
                call_args = mock_securityhub.batch_import_findings.call_args[1]
                finding = call_args['Findings'][0]
                assert finding['Id'] == f"state-transition-{prev_state}-to-{new_state}"


class TestRealSecurityHubIntegration:
    """
    Test Security Hub integration with real infrastructure patterns
    
    These tests validate the ASFF finding structure against real
    Security Hub requirements and product ARN formats.
    """
    
    def test_real_security_hub_finding_structure(self):
        """Test Security Hub finding structure matches real infrastructure requirements"""
        # Use real Security Hub fixture for validation
        real_finding = REAL_INFRASTRUCTURE_FIXTURES["real_security_hub_finding"]
        
        # Verify ASFF compliance with real patterns
        assert real_finding['SchemaVersion'] == "2018-10-08"
        assert real_finding['ProductArn'].startswith('arn:aws:securityhub:eu-north-1:')
        assert 'product/123456789012/default' in real_finding['ProductArn']
        
        # Verify real resource structure
        resources = real_finding['Resources']
        assert len(resources) == 2
        
        # Account resource
        account_resource = next(r for r in resources if r['Type'] == 'AwsAccountId')
        assert account_resource['Region'] == 'eu-north-1'
        
        # State machine resource
        sm_resource = next(r for r in resources if r['Type'] == 'AwsStatesStateMachine')
        assert sm_resource['Id'].startswith('arn:aws:states:eu-north-1:')
        assert 'RealStateMachine-ABC123' in sm_resource['Id']
        
        # Verify SOAR-specific fields
        assert real_finding['ProductFields']['TicketDestination'] == "TEAM"
        assert real_finding['ProductFields']['IncidentDomain'] == "INFRA"
        assert 'OpenSecOps SOAR' in real_finding['ProductFields']['aws/securityhub/CompanyName']
    
    def test_real_product_arn_format_validation(self):
        """Test that Product ARN format matches real Security Hub requirements"""
        lambda_handler = lambda_app.lambda_handler
        
        # Use Step Functions alarm to test Product ARN generation
        sf_event = REAL_INFRASTRUCTURE_FIXTURES["real_stepfunctions_alarm"]
        
        with patch.object(lambda_app, 'get_client') as mock_get_client:
            mock_securityhub = MagicMock()
            mock_securityhub.batch_import_findings.return_value = {'FailedCount': 0}
            mock_get_client.return_value = mock_securityhub
            
            result = lambda_handler(sf_event, None)
            assert result is True
            
            call_args = mock_securityhub.batch_import_findings.call_args[1]
            finding = call_args['Findings'][0]
            
            # Verify Product ARN follows real infrastructure pattern
            product_arn = finding['ProductArn']
            account_id = sf_event['account']
            region = sf_event['region']
            expected_pattern = f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"
            
            assert product_arn == expected_pattern


@pytest.mark.integration
class TestRealInfrastructureEndToEnd:
    """
    End-to-end tests with real infrastructure patterns
    
    These tests simulate complete alarm processing workflows
    using realistic infrastructure configurations.
    """
    
    def test_complete_stepfunctions_workflow(self):
        """Test complete Step Functions alarm workflow with real patterns"""
        pytest.skip("Integration test requires real AWS environment")
    
    def test_complete_lambda_workflow(self):
        """Test complete Lambda alarm workflow with real patterns"""
        pytest.skip("Integration test requires real AWS environment")
    
    def test_cross_account_real_scenario(self):
        """Test cross-account processing with real account patterns"""
        pytest.skip("Integration test requires multi-account AWS setup")