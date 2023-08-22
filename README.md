# all-alarms-to-sec-hub

This SAM project creates Security Hub findings for all CloudWatch Alarm Change events to the state ALARM.


## Deployment

First log in to your AWS organisation using SSO and a profile that gives you
AWSAdministratorAccess to the AWS Organizations admin account.

```console
aws sso login --profile <profile-name>
```

Then type:

```console
./deploy
```
