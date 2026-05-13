# Change Log

## v1.3.3
    * Security: bump `urllib3` floor to `>=2.7.0` in `boto3.in` (distributed from canonical `Installer/templates/boto3.in`) to remediate CVE-2026-44431 and CVE-2026-44432 (both affect urllib3 ≤ 2.6.3, fixed in 2.7.0). The pinned `boto3==1.42.94` previously resolved urllib3 transitively to 2.6.3; the new floor forces resolution to 2.7.0. Locks recompiled with `--upgrade`; other transitive deps refreshed to their latest in-range versions as a side effect (no code or behaviour change).

## v1.3.2
    * Enable auto-close workflow for external pull requests, enforcing the cathedral governance policy uniformly across all OpenSecOps repositories. Pull requests from non-team authors are closed automatically with a redirect comment pointing to the bug-report template, the GitHub Security Advisory flow, and the fork-under-MPL-2.0 path.
    * `SECURITY.md` §14 now carries a Trust-page cross-link ([opensecops.org/trust.html](https://www.opensecops.org/trust.html)) alongside the existing canonical supply-chain document link, positioning the Trust page as the lighter customer-facing synthesis.

## v1.3.1

- `SECURITY.md` and `README` updated re: OpenSSF Scorecard publication status. See [supply-chain documentation](https://github.com/OpenSecOps-Org/Documentation/blob/main/docs/security/supply-chain.md) §5.5.

## v1.3.0
    * Converted to OpenSecOps supply-chain framework: hash-pinned dependencies, signed releases, daily CVE scan, Scorecard. See `SECURITY.md`.

## v1.2.7
    * Fixed alarm resource extraction to use correct CloudWatch alarm event structure
    * Alarm configuration now correctly extracted from metrics[0].metricStat.metric path
    * Resource dimensions now properly accessed as dictionary instead of array
    * Enables SOAR enricher to receive accurate Step Functions and Lambda ARNs

## v1.2.6
    * CHANGELOG correction: v1.2.5 erroneously repeated functionality from v1.2.4

## v1.2.5
    * Enhanced timestamp handling with comprehensive edge case support using python-dateutil
    * Updated requirements.txt to include python-dateutil (removed boto3 as provided by Lambda runtime)
    * Added extensive test coverage for timestamp parsing edge cases and error scenarios

## v1.2.4
    * Fixed CloudWatch alarm timestamp accuracy for Security Hub findings
    * Now uses actual alarm trigger timestamp (newState.timestamp) instead of EventBridge processing time
    * Added FirstObservedAt and LastObservedAt fields with alarm trigger time for better SOAR correlation
    * Implemented extract_alarm_timestamp() function with proper fallback logic (CloudWatch -> EventBridge)
    * Converts CloudWatch timestamp format (+0000) to Security Hub ASFF format (Z)
    * SOAR enrichment can now search correct time windows around actual alarm trigger events
    * Eliminates timing gaps between alarm detection and Security Hub finding creation

## v1.2.3
    * Removed erroneous version number from lambda code

## v1.2.2
    * Release process correction

## v1.2.1
    * Release process correction

## v1.2.0
    * Initial attempt (incomplete release process)

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

