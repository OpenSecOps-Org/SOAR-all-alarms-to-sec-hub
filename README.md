# all-alarms-to-sec-hub

This SAM project creates Security Hub findings for all CloudWatch Alarm Change events to the state ALARM.


## Deployment

First make sure that your SSO setup is configured with a default profile giving you AWSAdministratorAccess
to your AWS Organizations administrative account. This is necessary as the AWS cross-account role used 
during deployment only can be assumed from that account.

```console
aws sso login
```

Then type:

```console
./deploy
```
