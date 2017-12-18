This AWS Lambda function allows auto-remediation of a user adding themself to an IAM group. Its setup is based on material found in [this post](https://aws.amazon.com/blogs/security/how-to-detect-and-automatically-revoke-unintended-iam-access-with-amazon-cloudwatch-events/) by Mustafa Torun on the AWS Security Blog and follows it closely, repurposing it to work for a slightly different task.

#### Step 1: Create an IAM role for the Lambda function ####

This step creates an IAM execution role for the Lambda function, giving it the
permissions that it needs to make changes to other user permissions and to log
its own actions.

This access policy defines those permissions and is found in the the file
`access_policy.json`:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowRemoveUserFromGroup",
            "Effect": "Allow",
            "Action": [
                "iam:RemoveUserFromGroup",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

This trust policy document is also necessary and is found in the file
`trust_policy.json`:

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Make sure to replace the example account number (123456789012) with your account number.
Create an execution role using these two policies by executing the following CLI
commands:

```
$ aws iam create-policy \
--policy-name AutoremediationIAMandLogs \
--policy-document file://access_policy.json

$ aws iam create-role \
--role-name IamAutoremediation \
--assume-role-policy-document file://trust_policy.json

$ aws iam attach-role-policy \
--role-name IamAutoremediation \
--policy-arn arn:aws:iam::123456789012:policy/AutoremediationIAMandLogs
```

#### Step 2: Create the Lambda function ####

The following lambda function will be triggered by a Cloudwatch event and gather
information from that event to reverse the action of a user adding themself
to an IAM group.

```
'use strict';

var aws = require('aws-sdk');
var iam = new aws.IAM();

exports.handler = function(event, context) {
    // Log the incoming Amazon CloudWatch Events event     
    console.log('Received event:', JSON.stringify(event, null, 2));

     // If the caller is not an IAM user, do nothing
     if (event.detail.userIdentity.type != 'IAMUser') {
         context.done();
     } else {
        var userName = event.detail.userIdentity.userName;

        // If the user is adding herself to a group
        if (event.detail.eventName === "AddUserToGroup" &&
                event.detail.requestParameters.userName === userName) {

            // Remove the user from that group
            var groupName = event.detail.requestParameters.groupName;
            console.log('User adding self to group detected. Removing user',
                            userName, 'from group', groupName);

            var params = {
                GroupName: groupName, 
                UserName: userName
            };
            iam.removeUserFromGroup(params, function(err, data) {
                if (err) {
                    console.log(err, err.stack);
                } else {
                    console.log(data);
                }
            });
        }
     }
  }
```

Run the following AWS CLI command to create the Lambda function:

Need to select the US East (N. Virgina) region (us-east-1)
IAM is a global service and its AWS API call events are only available in that
region.

```
$ zip lambda.zip lambda.js

$ aws lambda create-function \
--function-name UndoAddSelfToGroup \
--runtime nodejs6.10 \
--zip-file fileb://lambda.zip \
--handler lambda.handler \
--role arn:aws:iam:123456789012:role/IamAutoremediation \
--timeout 30
```

#### Step 3: Create a CloudWatch Events rule ####

This CloudWatch Events rule will look for the particular incoming event of a
user being added to an IAM group and is found in the file event_pattern.json:

```
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "iam.amazonaws.com"
    ],
    "eventName": [
      "AddUserToGroup"
    ]
  }
}
```

Run the following AWS CLI commands to create the CloudWatch Events rule, and add
the lambda function to it as a target:

```
$ aws events put-rule \
--name DetectAddUserToGroupCalls \
--event-pattern file://event_pattern.json

$ aws events put-targets \
--rule DetectAddUserToGroupCalls \
--targets \
Id=1,Arn=arn:aws:lambda:us-east-1:123456789012:function:UndoAddSelfToGroup
```

Run this command to allow CloudWatch Events to invoke the Lambda function:

```
$ aws lambda add-permission \
--function-name UndoAddSelfToGroup \
--statement-id AllowCloudWatchEventsToInvoke \
--action 'lambda:InvokeFunction' \
--principal events.amazonaws.com \
--source-arn \
arn:aws:events:us-east-1:123456789012:rule/DetectAddUserToGroupCalls
```

With all of these elements set up, instances of a user adding themself to a group will be automatically detected and reversed.
