# AWS resource grouping

`resource-group.cfn.yaml` creates one new AWS Resource Group. Its tag query selects supported resources in the deployment region with the project's unique `Project` tag value. It does not create or modify email identities, IAM credentials, SNS topics, or other workloads.

AWS groups organize resources by query rather than owning them as an Azure resource group does. Use dedicated resource names, scoped IAM permissions, and consistent tags on each project-owned AWS resource. Never retag unrelated resources to make them appear in this group.

## Deploy

Authenticate the AWS CLI with the intended account. Copy `deployment.local.ps1.example` to `deployment.local.ps1` and fill the region, stack name, group name, and unique project tag value. That local file and deployment results stay ignored.

```powershell
. ./infra/aws/deployment.local.ps1
aws sts get-caller-identity
aws cloudformation validate-template --region $awsRegion --template-body file://infra/aws/resource-group.cfn.yaml
aws cloudformation deploy --region $awsRegion --stack-name $awsStackName --template-file infra/aws/resource-group.cfn.yaml --parameter-overrides "GroupName=$awsGroupName" "ProjectTagValue=$awsProjectTagValue" --tags "Project=$awsProjectTagValue" --no-fail-on-empty-changeset
```

Deploy only after the owner approves the group. This template needs CloudFormation permissions and Resource Groups create/read/tag permissions, but creates no IAM resources and requests no IAM capabilities.

## Verify

```powershell
aws resource-groups get-group --region $awsRegion --group-name $awsGroupName
aws resource-groups get-group-query --region $awsRegion --group-name $awsGroupName
aws resource-groups list-group-resources --region $awsRegion --group-name $awsGroupName
```

Verify the exact group name, the `TAG_FILTERS_1_0` query, the `Project` filter, and the absence of unrelated members. Before email provisioning it may contain only administrative resources such as its own stack. When later resources are created, allow for tag indexing before verifying membership.

Use `AWS::AllSupported` so new supported types can appear without broadening the project tag. AWS's supported-types list includes SES identities/configuration sets and SNS topics for tag-based groups. IAM roles are not supported by tag-based groups and IAM users are not listed, so do not promise that every IAM resource will appear in the group. Those resources still need dedicated project names, scoped permissions, and project tags where supported. Check current grouping support when adding any resource type.

Sources: [Resource Groups concepts](https://docs.aws.amazon.com/ARG/latest/userguide/), [supported resource types](https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html), [CloudFormation group schema](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-resourcegroups-group.html).
