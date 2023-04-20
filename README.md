# all-alarms-to-sec-hub

This SAM project creates Security Hub findings for all CloudWatch Alarm Change events to the state ALARM.

1. Install template.yaml (containing the lambda and the event rule that triggers it from the local event bus) by using `./deploy-all` to the **Security** account in each of your chosen regions.

2. Then use the template `local-alarm-events-to-sec-hub-bus` to create a StackSet in the **Organization** account in your main region, deploying to all accounts in all chosen regions. It will set up a role and a rule to transfer local alarm events to the security account.

3. Next, deploy `local-alarm-events-to-sec-hub-bus` manually as a normal stack (not a StackSet) to the **Organisation** account in each chosen region. You must do this as a manual extra step, as StackSets never deploy to the organisation account itself.
