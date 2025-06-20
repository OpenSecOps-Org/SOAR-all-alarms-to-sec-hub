# Change Log

## v1.2.0
    * Fixed CloudWatch alarm timestamp accuracy for Security Hub findings
    * Now uses actual alarm trigger timestamp (newState.timestamp) instead of EventBridge processing time
    * Added FirstObservedAt and LastObservedAt fields with alarm trigger time for better SOAR correlation
    * Implemented extract_alarm_timestamp() function with proper fallback logic (CloudWatch -> EventBridge)
    * Converts CloudWatch timestamp format (+0000) to Security Hub ASFF format (Z)
    * SOAR enrichment can now search correct time windows around actual alarm trigger events
    * Eliminates timing gaps between alarm detection and Security Hub finding creation

## v1.1.0
    * Enhanced Security Hub findings to include monitored AWS resources extracted from alarm configuration
    * Added support for Step Functions and Lambda resource extraction (app.py:extract_monitored_resource)
    * Security Hub findings now contain both origin account and actual monitored resource ARNs
    * Changes enable SOAR enrichment to use actual resource ARNs instead of alarm description parsing

## v1.0.9
    * Updated GitHub remote references in publish.zsh script to use only OpenSecOps-Org, removed Delegat-AB
    * Updated default company name from 'Delegat SOAR Infrastructural Alarms' to 'OpenSecOps SOAR Infrastructural Alarms'

## v1.0.8
    * Updated GitHub organization name from CloudSecOps-Org to OpenSecOps-Org.
    * Updated references to CloudSecOps-Installer to Installer.

## v1.0.7
    * File paths corrected for the new name of the installer.

## v1.0.6
    * Updated LICENSE file to MPL 2.0.

## v1.0.5
    * Updated publish.zsh to support dual-remote publishing to CloudSecOps-Org repositories.

## v1.0.4
    * Python v3.12.2.
    * `.python-version` file to support `pyenv`.

## v1.0.3
    * Refreshed scripts.

## v1.0.2
    * Open-source credits and URLs
    * Fixed installer initial stackset creation.

## v1.0.1
    * `--dry-run` and `--verbose` added to `deploy`.

## v1.0.0.
* First release

