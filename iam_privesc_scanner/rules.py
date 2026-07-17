# iam_privesc_scanner/rules.py

# A mapping of privilege escalation vector names to the required IAM actions.
# These vectors are based on common AWS IAM privilege escalation techniques,
# such as those documented by Rhino Security Labs.

PRIVESC_VECTORS = {
    "CreateAccessKey": [
        "iam:CreateAccessKey"
    ],
    "CreateLoginProfile": [
        "iam:CreateLoginProfile"
    ],
    "UpdateLoginProfile": [
        "iam:UpdateLoginProfile"
    ],
    "AttachUserPolicy": [
        "iam:AttachUserPolicy"
    ],
    "AttachGroupPolicy": [
        "iam:AttachGroupPolicy"
    ],
    "AttachRolePolicy": [
        "iam:AttachRolePolicy"
    ],
    "PutUserPolicy": [
        "iam:PutUserPolicy"
    ],
    "PutGroupPolicy": [
        "iam:PutGroupPolicy"
    ],
    "PutRolePolicy": [
        "iam:PutRolePolicy"
    ],
    "AddUserToGroup": [
        "iam:AddUserToGroup"
    ],
    "UpdateAssumeRolePolicy": [
        "iam:UpdateAssumeRolePolicy"
    ],
    "PassRoleWithEC2": [
        "iam:PassRole",
        "ec2:RunInstances"
    ],
    "PassRoleWithLambda": [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction"
    ],
    "PassRoleWithGlue": [
        "iam:PassRole",
        "glue:CreateDevEndpoint"
    ],
    "PassRoleWithCloudFormation": [
        "iam:PassRole",
        "cloudformation:CreateStack"
    ],
    "PassRoleWithDataPipeline": [
        "iam:PassRole",
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
        "datapipeline:ActivatePipeline"
    ],
    "SetDefaultPolicyVersion": [
        "iam:SetDefaultPolicyVersion"
    ],
    "CreatePolicyVersion": [
        "iam:CreatePolicyVersion"
    ]
}
