from aws_api import AWSAPI


class DiagnosticD:
    def __init__(self, credentials_file):
        self.aws_api = AWSAPI(credentials_file)

    # EBS 및 볼륨 암호화 설정 - 자동화
    # 완성
    def D01(self):
        evidence = []
        volumes = self.aws_api.get_volumes()

        for volume in volumes:
            volume_id = volume["VolumeId"]
            encrypted = volume["Encrypted"]
            volume_name = self.aws_api._get_volume_name(volume.get("Tags", []))

            if not encrypted:
                evidence.append({"VolumeName": volume_name, "VolumeId": volume_id, "Size": volume["Size"], "State": volume["State"], "AvailabilityZone": volume["AvailabilityZone"]})
                
        return self.aws_api.evaluate_result(evidence, "EBS 및 볼륨 리소스에 암호화가 설정되어 있지 않습니다.", "양호합니다.")

    # RDS 암호화 설정 - 자동화
    # 완성
    def D02(self):
        evidence = []
        instances = self.aws_api.get_db_instances()

        for instance in instances:
            instance_id = instance["DBInstanceIdentifier"]
            is_encrypted = instance.get("StorageEncrypted", False)
            engine = instance["Engine"]

            # 암호화되지 않은 인스턴스 수집
            if not is_encrypted:
                evidence.append({"DBInstanceIdentifier": instance_id, "Engine": engine, "StorageEncrypted": is_encrypted})
                
        return self.aws_api.evaluate_result(evidence, "RDS 데이터베이스 암호화가 활성화되어 있지 않습니다.", "양호합니다.")

    # S3 암호화 설정 - 자동화
    # 완성 (추후 S3 설정 후 재검토!!!!!!!!!!!!!)
    def D03(self):
        evidence = []
        buckets = self.aws_api.get_s3_buckets()

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                # 버킷 암호화 상태 확인
                encryption = self.aws_api.get_bucket_encryption(bucket_name)
                rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

                # SSE-S3 또는 SSE-KMS 사용 여부 확인
                if not any(rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] in ["AES256", "aws:kms"] for rule in rules):
                    evidence.append({"BucketName": bucket_name, "EncryptionConfigured": False})

            except self.aws_api.s3_client.exceptions.ClientError as e:
                # 암호화 설정이 없는 버킷 처리
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    evidence.append({"BucketName": bucket_name, "EncryptionConfigured": False})

                else:
                    print(f"Error checking bucket {bucket_name}: {e}")
                
        return self.aws_api.evaluate_result(evidence, "S3 버킷에 관한 암호화가 안전하지 않습니다.", "양호합니다.")

    # 통신구간 암호화 설정 - 자동화
    # 완성 (추후 로드밸런싱 추가 후 재검토!!!!!!!)
    def D04(self):
        evidence = []
        apis = self.aws_api.get_rest_apis()
        load_balancers = self.aws_api.get_load_balancers()
        vpn_connections = self.aws_api.get_vpn_connections()

        # API Gateway에서 HTTPS가 활성화되었는지 확인
        for api in apis:
            api_id = api["id"]
            stages = self.aws_api.get_stages(api_id)
            for stage in stages:
                if not stage.get("methodSettings", {}).get("*/*", {}).get("requireSecureTransport", False):
                    evidence.append({"Type": "APIsWithoutHTTPS", "APIName": api.get("name"), "Stage": stage.get("stageName")})


        # Application Load Balancer와 Network Load Balancer에서 HTTPS가 활성화되었는지 확인
        for lb in load_balancers:
            lb_arn = lb["LoadBalancerArn"]
            listeners = self.aws_api.get_listeners(lb_arn)
            for listener in listeners:
                if listener["Protocol"] not in ["HTTPS", "TLS"]:
                    evidence.append({"Type": "LoadBalancersWithoutTLS", "LoadBalancerName": lb["LoadBalancerName"], "Protocol": listener["Protocol"]})

        # VPN 연결에서 암호화가 설정되었는지 확인
        for vpn in vpn_connections:
            if vpn["Options"].get("TunnelOptions", [{}])[0].get("PreSharedKey", None) is None:
                evidence.append({"Type": "VPNConnectionsWithoutEncryption", "VPNConnectionId": vpn["VPNConnectionId"], "State": vpn["State"]})
                
        return self.aws_api.evaluate_result(evidence, "클라우드 리소스 통신 구간 내 암호화 설정이 미흡합니다.", "양호합니다.")

    # CloudTrail 암호화 설정 - 자동화
    # 완성 (기회되면 테스트)
    def D05(self):
        evidence = []
        trails = self.aws_api.get_trails()

        for trail in trails:
            trail_name = trail["Name"]
            kms_key_id = trail.get("KmsKeyId")

            # SSE-KMS가 설정되지 않은 Trail 추가
            if not kms_key_id:
                evidence.append({"TrailName": trail_name, "SSEKMSConfigured": False})
                
        return self.aws_api.evaluate_result(evidence, "CloudTrail 암호화 설정이 미흡합니다.", "양호합니다.")

    # CloudWatch 암호화 설정 - 자동화
    # 완성
    def D06(self):
        evidence = []
        log_groups = self.aws_api.get_log_groups()

        for log_group in log_groups:
            log_group_name = log_group["logGroupName"]
            kms_key_id = log_group.get("kmsKeyId")

            # KMS 키 ARN이 설정되지 않은 로그 그룹 추가
            if not kms_key_id:
                evidence.append({"LogGroupName": log_group_name, "KMSKeyConfigured": False})
                
        return self.aws_api.evaluate_result(evidence, "CloudWatch 암호화 설정이 미흡합니다.", "양호합니다.")

    # AWS 사용자 계정 로깅 설정 - 자동화
    # 완성 (기회되면 테스트)
    def D07(self):
        evidence = []

        try:
            trails = self.aws_api.get_trails()

            if not trails:
                evidence.append({"CloudTrail 기능 자체 없음"})

            for trail in trails:
                trail_name = trail["Name"]
                trail_status = self.aws_api.get_trail_status(trail_name)
                is_logging = trail_status.get("IsLogging", False)

                # 로깅 비활성화된 Trail 추가
                if not is_logging:
                    evidence.append({"TrailName": trail_name, "LoggingEnabled": False})
        
        except Exception as e:
            print(f"Error occurred: {e}")

        return self.aws_api.evaluate_result(evidence, "AWS 사용자 계정 로깅 설정이 미흡합니다.", "양호합니다.")

    # 인스턴스 로깅 설정 - 자동화
    # 완성
    def D08(self):
        evidence = []

        # EC2 인스턴스 정보 가져오기
        instances = self.aws_api.get_instances()

        # describe_instances() 결과가 딕셔너리라고 가정
        if isinstance(instances, dict) and "Reservations" in instances:
            instance_ids = [
                instance["InstanceId"]
                for reservation in instances["Reservations"]
                for instance in reservation["Instances"]
            ]
        else:
            # describe_instances() 결과가 리스트인 경우
            instance_ids = [
                instance["InstanceId"]
                for reservation in instances
                for instance in reservation.get("Instances", [])
            ]

        # CloudWatch 로그 그룹 목록 가져오기
        log_groups = self.aws_api.get_log_groups()

        # CloudWatch 로그 그룹 및 로그 스트림 검사
        for instance_id in instance_ids:
            has_logs = False
            for log_group in log_groups:
                log_group_name = log_group["logGroupName"]
                log_streams = self.aws_api.get_log_streams(log_group_name, instance_id)

                if log_streams:
                    has_logs = True
                    break

            if not has_logs:
                evidence.append({"InstancesWithoutLogStreams": instance_id})

        return self.aws_api.evaluate_result(evidence, "인스턴스 로깅 설정이 미흡합니다.", "양호합니다.")

    # RDS 로깅 설정 - 자동화
    # 완성
    def D09(self):
        evidence = []

        # 모든 RDS 인스턴스 가져오기
        db_instances = self.aws_api.get_db_instances()

        for db_instance in db_instances:
            db_instance_identifier = db_instance["DBInstanceIdentifier"]

            # RDS 로그 설정 확인
            log_exports = db_instance.get("EnabledCloudwatchLogsExports", [])
            if not log_exports:
                evidence.append({"Type": "RDSInstancesWithoutLogStreams", "DBInstanceIdentifier": db_instance_identifier, "LogStreamsConfigured": False, "Details": "CloudWatch 로그 미설정"})

            # CloudWatch 로그 그룹 확인
            log_group_prefix = f"/aws/rds/instance/{db_instance_identifier}"
            log_groups = self.aws_api.get_log_groups_prefix(log_group_prefix)

            if not log_groups:
                evidence.append({"Type": "RDSInstancesWithoutLogStreams", "DBInstanceIdentifier": db_instance_identifier, "LogStreamsConfigured": False, "Details": "CloudWatch 로그 그룹 미설정"})


        return self.aws_api.evaluate_result(evidence, "RDS 로깅 설정이 미흡합니다.", "양호합니다.")

    # S3 로깅 설정 - 자동화
    # 완성 (추후 S3버킷 설정 후 재검토!!!!!)
    def D10(self):
        evidence = []
        buckets = self.aws_api.get_s3_buckets()

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # 버킷 로깅 설정 확인
            logging_status = self.aws_api.get_bucket_logging(bucket_name)

            if "LoggingEnabled" not in logging_status:
                evidence.append({"BucketName": bucket_name, "AccessLoggingEnabled": False})

        return self.aws_api.evaluate_result(evidence, "S3 로깅 설정이 미흡합니다.", "양호합니다.")

    # VPC 플로우 로깅 설정 - 자동화
    # 완성 (기회되면 테스트)
    def D11(self):
        evidence = []

        # 모든 VPC 가져오기
        vpcs = self.aws_api.get_vpcs()

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]

            # 플로우 로그 상태 확인
            flow_logs = self.aws_api.get_flow_logs(vpc_id)

            if not flow_logs:
                evidence.append({"VpcId": vpc_id, "FlowLogsConfigured": False})

        return self.aws_api.evaluate_result(evidence, "VPC 플로우 로깅 설정이 미흡합니다.", "양호합니다.")

    # 로그 보관 기간 설정 - 자동화
    # 완성 (기회되면 테스트)
    def D12(self):
        evidence = []

        # 로그 그룹 목록 가져오기
        log_groups = self.aws_api.get_log_groups()

        for log_group in log_groups:
            log_group_name = log_group["logGroupName"]
            retention_in_days = log_group.get("retentionInDays", None)

            # 보관 기간이 없거나 1년 미만인 경우
            if retention_in_days is None or retention_in_days < 365:
                evidence.append({"LogGroupName": log_group_name, "RetentionInDays": retention_in_days if retention_in_days else "Not Set"})

        return self.aws_api.evaluate_result(evidence, "로그 보관 기간 설정이 미흡합니다.", "양호합니다.")

    # 백업 사용 여부 - 일부 자동화
    # 완성 (현재 백업정책 여부 및 백업 계획에 리소스 연결 여부만 확인, 자세한 내용은 추후 커스터마이징 필요)
    def D13(self):
        evidence = []

        # 모든 백업 계획 가져오기
        backup_plans = self.aws_api.get_backup_plans()

        if not backup_plans:
            evidence.append({"Issue": "백업 정책 없음"})

        for plan in backup_plans:
            plan_id = plan["BackupPlanId"]
            plan_name = plan["BackupPlanName"]

            # 백업 계획에 리소스가 연결되어 있는지 확인
            selections = self.aws_api.get_backup_selections(plan_id)

            if not selections:
                evidence.append({"Issue": "백업 계획에 리소스가 연결되어 있지 않음", "BackupPlanId": plan_id, "BackupPlanName": plan_name})

        return self.aws_api.evaluate_result(evidence, "백업 사용 설정이 미흡합니다.", "양호합니다.")
