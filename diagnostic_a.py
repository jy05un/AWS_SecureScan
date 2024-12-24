from aws_api import AWSAPI
from datetime import datetime, timedelta


class DiagnosticA:
    def __init__(self, credentials_file):
        self.aws_api = AWSAPI(credentials_file)

    # 사용자 계정 관리 - 자동화
    # 완료
    def A01(self):
        evidence = []
        users = self.aws_api.get_iam_users()
        days_threshold = 90

        for user in users:
            user_name = user["UserName"]
            groups = self.aws_api.get_group_users(user_name)
            policies = self.aws_api.get_user_policies(user_name)

            # 진단용 사용자 제외
            if self.aws_api._exclude_diagnostic_user(user_name):
                continue

            if not groups:
                evidence.append({"IAM 그룹에 포함되지 않은 사용자 발견": user_name})

            for policy in policies:
                if policy["PolicyName"] == "AdministratorAccess":
                    evidence.append({"Administrator Access 권한 사용자 발견": user_name})

            unused_keys = self.aws_api.check_unused_access_keys(user_name, days_threshold)
            if unused_keys:
                evidence.append({"미사용 계정 발견": user_name, "UnusedKeys": unused_keys})

        return self.aws_api.evaluate_result(evidence, "관리자 권한 또는 불필요한 계정이 존재합니다.", "양호합니다.")


    # IAM 사용자 계정 단일화 관리 - 자동화
    # 완성 (MFA 디바이스 활성화를 통해서 확인)
    def A02(self):
        evidence = []
        users = self.aws_api.get_iam_users()

        for user in users:
            user_name = user["UserName"]

            # 진단용 사용자 제외
            if self.aws_api._exclude_diagnostic_user(user_name):
                continue

            mfa_enabled = self.aws_api.get_user_mfa_status(user_name)
            evidence.append({"UserName": user_name, "MFAEnabled": mfa_enabled})
            

        return self.aws_api.evaluate_result(evidence, "IAM 비단일화 계정이 존재합니다.", "양호합니다.")
        
    # IAM 사용자 계정 식별 관리 - 자동화
    # 완성 (Name, Email, Department 태그 필수)
    def A03(self):
        evidence = []
        users = self.aws_api.get_iam_users()
        required_tags = ["Name", "Email", "Department"]

        for user in users:
            user_name = user["UserName"]

            # 진단용 사용자 제외
            if self.aws_api._exclude_diagnostic_user(user_name):
                continue

            tags = self.aws_api.iam_client.list_user_tags(UserName=user_name).get("Tags", [])
            user_tags = {tag["Key"]: tag["Value"] for tag in tags}
            missing_tags = [tag for tag in required_tags if tag not in user_tags]
            

            if missing_tags:
                evidence.append({"UserName": user_name, "MissingTags": missing_tags})

        return self.aws_api.evaluate_result(evidence, "IAM 사용자 태그가 미흡합니다.", "양호합니다.")

    # IAM 그룹 사용자 계정 관리 - 자동화
    # 완성 (장기간 미로그인 계정 기반)
    def A04(self):
        evidence = []
        inactive_days_threshold = 90
        current_time = datetime.utcnow()
        groups = self.aws_api.get_iam_groups()

        for group in groups:
            group_name = group["GroupName"]
            users = self.aws_api.get_group(group_name)

            for user in users:
                user_name = user["UserName"]
                
                # 진단용 사용자 제외
                if self.aws_api._exclude_diagnostic_user(user_name):
                    continue

                last_login = self.aws_api.get_last_login(user_name)

                if not last_login:
                    evidence.append({"UserName": user_name, "GroupName": group_name, "LastLogin": "Never"})
                else:
                    last_login = last_login.replace(tzinfo=None)
                    inactive_days = (current_time - last_login).days
                    if inactive_days > inactive_days_threshold:
                        evidence.append({
                            "UserName": user_name,
                            "GroupName": group_name,
                            "LastLogin": last_login.strftime("%Y-%m-%d"),
                            "InactiveDays": inactive_days
                        })

        return self.aws_api.evaluate_result(evidence, "불필요한 계정이 존재합니다.", "양호합니다.")

    # Key Pair 접근 관리 - 자동화
    # 완성
    def A05(self):
        evidence = []
        instances = self.aws_api.ec2_client.describe_instances()["Reservations"]

        for reservation in instances:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]
                key_name = instance.get("KeyName")
                if key_name:
                    evidence.append({"InstanceId": instance_id, "KeyName": key_name})

        return self.aws_api.evaluate_result(evidence, "키 페어를 통해 EC2에 접근합니다.", "양호합니다.")

    # Key Pair 보관 관리 - 불가능
    def A06(self):
        return {"weak": True, "message": "진단 불가", "evidence": "수동 진단을 실시해주세요."}

    # Admin Console 관리자 정책 관리 - 자동화
    # 완성 (일부 자동화, 우선 IAM 그룹에 속하지 않으면서도 admin 권한을 가지고 있으면서도 최근에 사용된 계정)
    def A07(self):
        evidence = []
        users = self.aws_api.get_iam_users()
        days_threshold = 5

        for user in users:
            user_name = user["UserName"]

            # 진단용 사용자 제외
            if self.aws_api._exclude_diagnostic_user(user_name):
                continue

            groups = self.aws_api.get_group_users(user_name)
            policies = self.aws_api.get_user_policies(user_name)

            if not groups:
                evidence.append({"IAM 그룹에 포함되지 않은 사용자 발견": user_name})

            for policy in policies:
                if policy["PolicyName"] == "AdministratorAccess":
                    evidence.append({"Administrator Access 권한 사용자 발견": user_name})

            unused_keys = self.aws_api.check_unused_access_keys(user_name, days_threshold)
            if unused_keys:
                evidence.append({"최근 사용된 계정": user_name, "UnusedKeys": unused_keys})

        return self.aws_api.evaluate_result(evidence, "서비스 용도로 Admin Console 계정 사용 의심합니다.", "양호합니다.")

    # Admin Console 및 Access Key 계정 활성화 및 사용주기 관리 - 자동화
    # 완성
    def A08(self):
        evidence = []
        admin_access_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        admin_users = []
        sixty_days_ago = datetime.utcnow() - timedelta(days=60)

        users = self.aws_api.get_iam_users()
        for user in users:
            user_name = user["UserName"]

            # 진단용 사용자 제외
            if self.aws_api._exclude_diagnostic_user(user_name):
                continue

            policies = self.aws_api.get_user_policies(user_name)
            if any(policy["PolicyArn"] == admin_access_policy_arn for policy in policies):
                admin_users.append(user_name)

        for admin_user in admin_users:
            access_keys = self.aws_api.iam_client.list_access_keys(UserName=admin_user)["AccessKeyMetadata"]
            for key in access_keys:
                create_date = key["CreateDate"].replace(tzinfo=None)
                if create_date > sixty_days_ago:
                    evidence.append({
                        "UserName": admin_user,
                        "KeyId": key["AccessKeyId"],
                        "CreateDate": create_date.strftime('%Y-%m-%d %H:%M:%S')
                    })

        try:
            root_access_keys = self.aws_api.iam_client.list_access_keys(UserName="root")["AccessKeyMetadata"]
            if root_access_keys:
                evidence.append({"RootAccessKeyExists": True})
        except self.aws_api.iam_client.exceptions.NoSuchEntityException:
            pass

        return self.aws_api.evaluate_result(evidence, "루트 또는 Admin Console 계정의 Access Key 사용 주기가 60일 초과하였습니다.", "양호합니다.")

    # 자동화
    def A09(self):
        evidence = []
        user_name = "root"

        try:
            root_mfa_devices = self.aws_api.get_mfa_devices(user_name)
            if not root_mfa_devices:
                evidence.append({"RootMFA": "Disabled"})
        except self.aws_api.iam_client.exceptions.NoSuchEntityException:
            pass

        users = self.aws_api.get_iam_users()
        for user in users:
            user_name = user["UserName"]

            # 진단용 사용자 제외
            if self.aws_api._exclude_diagnostic_user(user_name):
                continue

            if not self.aws_api.get_user_mfa_status(user_name):
                evidence.append({"UserName": user_name, "MFAEnabled": False})

        return self.aws_api.evaluate_result(evidence, "MFA가 비활성화된 계정이 존재합니다.", "양호합니다.")

    # AWS 계정 패스워드 정책 관리 - 자동화
    # 완성
    def A10(self):
        evidence = []
        try:
            policy = self.aws_api.get_account_password_policy()

            min_length = policy.get("MinimumPasswordLength", 0)
            complexity_requirements = {
                "RequireUppercaseCharacters": policy.get("RequireUppercaseCharacters", False),
                "RequireLowercaseCharacters": policy.get("RequireLowercaseCharacters", False),
                "RequireNumbers": policy.get("RequireNumbers", False),
                "RequireSymbols": policy.get("RequireSymbols", False),
            }
            complexity_count = sum(complexity_requirements.values())

            max_age = policy.get("MaxPasswordAge", 0)
            reuse_prevention = policy.get("PasswordReusePrevention", 0)

            if max_age > 90:
                evidence.append({"Reason": "패스워드 만료 기간 90일 초과"})

            if reuse_prevention == 0:
                evidence.append({"Reason": "패스워드 재사용 제한 없음"})

            if complexity_count < 2:
                evidence.append({"Reason": "복잡성 기준 2종류 미만 허용"})

            if complexity_count == 2 and min_length < 10:
                evidence.append({"Reason": "패스워드 최소 10자리 미만 허용"})

            if complexity_count == 3 and min_length < 8:
                evidence.append({"Reason": "패스워드 최소 8자리 미만 허용"})

        except self.aws_api.iam_client.exceptions.NoSuchEntityException:
            evidence.append({"Reason": "IAM 기본 정책 사용 또는 패스워드 정책이 설정되지 않음"})
        except Exception as e:
            evidence.append({"Reason": "IAM 기본 정책 사용 또는 패스워드 정책이 설정되지 않음"})

        return self.aws_api.evaluate_result(evidence, "IAM 계정의 패스워드 복잡성 기준 미준수입니다.", "양호합니다.")