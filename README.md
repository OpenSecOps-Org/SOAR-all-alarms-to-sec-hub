# all-alarms-to-sec-hub

This SAM project creates Security Hub findings for all CloudWatch Alarm Change events to the state ALARM.


## Deployment

First log in to your AWS organisation using SSO and a default profile that gives you AWSAdministratorAccess.

```console
aws sso login
```

Then type:

```console
./deploy
```
