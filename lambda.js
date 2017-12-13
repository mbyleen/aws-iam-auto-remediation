'use strict';

var aws = require('aws-sdk');
var iam = new aws.IAM();

exports.handler = function(event, context) {
    // Log the incoming Amazon CloudWatch Events event
    console.log('Received event:', JSON.stringify(event, null, 2));

    // If the user is adding themself to a group
    var userName = event.detail.userIdentity.userName;
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
