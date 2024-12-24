from aws_api import AWSAPI


class DiagnosticB:
    def __init__(self, credentials_file):
        self.aws_api = AWSAPI(credentials_file)

    # 인스턴스 서비스 정책 관리 - 일부 자동화
    # 완성 (각 서비스마다 필수한 정책이 아닌 과도한 정책이 부여했는지 확인)
    def B01(self):
        # 서비스별 과도한 정책 이름
        service_policies = {
                "EC2": "AmazonEC2FullAccess",
                "ECS": "AmazonECS_FullAccess",
                "ECR": "AmazonEC2ContainerRegistryFullAccess",
                "EKS": "AmazonEKSClusterPolicy",
                "EFS": "AmazonElasticFileSystemFullAccess",
                "RDS": "AmazonRDSFullAccess",
                "S3": "AmazonS3FullAccess",
        }

        evidence = self.aws_api._check_policies(service_policies)

        return self.aws_api.evaluate_result(evidence, "과도한 정책이 설정되었습니다.", "양호합니다.")

    # 네트워크 서비스 정책 관리 - 일부 자동화
    # 완성 (각 서비스마다 필수한 정책이 아닌 과도한 정책이 부여했는지 확인)
    def B02(self):
        service_policies = {
            "VPC": "AmazonVPCFullAccess",
            "CloudFront": "CloudFrontFullAccess",
            "Route53": "AmazonRoute53FullAccess",
            "API Gateway": "AmazonAPIGatewayAdministrator",
            "Direct Connect": "AWSDirectConnectFullAccess",
            "AppMesh": "AWSAppMeshFullAccess",
            "CloudMap": "AWSCloudMapFullAccess",
        }

        evidence = self.aws_api._check_policies(service_policies)

        return self.aws_api.evaluate_result(evidence, "과도한 정책이 설정되었습니다.", "양호합니다.")

    # 기타 서비스 정책 관리- 일부 자동화
    # 완성 (각 서비스마다 필수한 정책이 아닌 과도한 정책이 부여했는지 확인)
    def B03(self):
        # 서비스별 과도한 정책 이름
        service_policies = {
            "Organizations": "AWSOrganizationsFullAccess",
            "CloudWatch": "CloudWatchFullAccess",
            "Auto Scaling": "AutoScalingFullAccess",
            "CloudFormation": "AWSCloudFormationFullAccess",
            "CloudTrail": "AWSCloudTrail_FullAccess",
            "Config": "AWSConfigMultiAccountSetupPolicy",
            "System Manager": "AWSSystemsManagerChangeManagementServicePolicy",
            "GuardDuty": "AmazonGuardDutyFullAccess",
            "Inspector": "AmazonInspectorFullAccess",
            "Single Sign-On": "AWSSSODirectoryAdministrator",
            "Certificate Manager": "AWSCertificateManagerFullAccess",
            "KMS": "AWSKeyManagementServicePowerUser",
            "WAF": "AWSWAFFullAccess",
            "Shield": "AWSShieldDRTAccessPolicy",
            "Security Hub": "AWSSecurityHubFullAccess",
            "Data Pipeline": "AWSDataPipeline_FullAccess",
            "Glue": "AWSGlueConsoleFullAccess",
            "MSK": "AmazonMSKFullAccess",
            "Backup": "AWSBackupFullAccess",
        }

        evidence = self.aws_api._check_policies(service_policies)

        return self.aws_api.evaluate_result(evidence, "과도한 정책이 설정되었습니다.", "양호합니다.")