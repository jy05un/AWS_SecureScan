from datetime import datetime
import json
import boto3


# AWS 자격 증명을 별도의 파일에서 읽어오기
def load_aws_credentials(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

class AWSAPI:
    def __init__(self, credentials_file):
        credentials = load_aws_credentials(credentials_file)
        self.iam_client = boto3.client("iam", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.ec2_client = boto3.client("ec2", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.s3_client = boto3.client("s3", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.rds_client = boto3.client("rds", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.apigateway_client = boto3.client("apigateway", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.elbv2_client = boto3.client("elbv2", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.cloudtrail_client = boto3.client("cloudtrail", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.logs_client = boto3.client("logs", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.backup_client = boto3.client("backup", aws_access_key_id=credentials['access_key'], aws_secret_access_key=credentials['secret_key'], region_name=credentials['region_name'])
        self.required_azs = ["ap-southeast-2a", "ap-southeast-2c"]
        self.diagnostic_user = credentials['diagnostic_user']

    def _exclude_diagnostic_user(self, user_name):
        return user_name == self.diagnostic_user

    def get_iam_users(self):
        return self.iam_client.list_users()["Users"]
    
    def get_iam_groups(self):
        return self.iam_client.list_groups()["Groups"]
    
    def get_iam_roles(self):
        return self.iam_client.list_roles()["Roles"]
    
    def get_account_password_policy(self):
        return self.iam_client.get_account_password_policy()["PasswordPolicy"]
    
    def get_s3_buckets(self):
        return self.s3_client.list_buckets()["Buckets"]
    
    def get_vpcs(self):
        return self.ec2_client.describe_vpcs()["Vpcs"]
    
    def get_volumes(self):
        return self.ec2_client.describe_volumes()["Volumes"]
    
    def get_security_groups(self):
        return self.ec2_client.describe_security_groups()["SecurityGroups"]
    
    def get_network_acls(self):
        return self.ec2_client.describe_network_acls()["NetworkAcls"]
    
    def get_route_tables(self):
        return self.ec2_client.describe_route_tables()["RouteTables"]
    
    def get_internet_gateways(self):
        return self.ec2_client.describe_internet_gateways()["InternetGateways"]
    
    def get_nat_gateways(self):
        return self.ec2_client.describe_nat_gateways()["NatGateways"]
    
    def get_instances(self):
        return self.ec2_client.describe_instances()["Reservations"]
    
    def get_vpn_connections(self):
        return self.ec2_client.describe_vpn_connections()["VpnConnections"]
    
    def get_db_subnet_groups(self):
        return self.rds_client.describe_db_subnet_groups()["DBSubnetGroups"]
    
    def get_db_instances(self):
        return self.rds_client.describe_db_instances()["DBInstances"]
    
    def get_rest_apis(self):
        return self.apigateway_client.get_rest_apis()["items"]
    
    def get_load_balancers(self):
        return self.elbv2_client.describe_load_balancers()["LoadBalancers"]
    
    def get_trails(self):
        return self.cloudtrail_client.describe_trails()["trailList"]
    
    def get_log_groups(self):
        return self.logs_client.describe_log_groups()["logGroups"]
    
    def get_backup_plans(self):
        return self.backup_client.list_backup_plans()["BackupPlansList"]

        
    def get_user_policies(self, user_name):
        return self.iam_client.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]
    
    def get_group_policies(self, group_name):
        return self.iam_client.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]
    
    def get_role_policies(self, role_name):
        return self.iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    
    def get_group_users(self, user_name):
        return self.iam_client.list_groups_for_user(UserName=user_name)["Groups"]
    
    def get_group(self, group_name):
        return self.iam_client.get_group(GroupName=group_name)["Users"]
    
    def get_mfa_devices(self, user_name):
        return self.iam_client.list_mfa_devices(UserName=user_name)["MFADevices"]
    
    def get_flow_logs(self, vpc_id):
        return self.ec2_client.describe_flow_logs(Filters=[{"Name": "resource-id", "Values": [vpc_id]}]).get("FlowLogs", [])
    
    def get_stages(self, api_id):
        return self.apigateway_client.get_stages(restApiId=api_id)["item"]
    
    def get_listeners(self, lb_arn):
        return self.elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]

    def get_user_mfa_status(self, user_name):
        return len(self.iam_client.list_mfa_devices(UserName=user_name)["MFADevices"]) > 0
    
    def get_last_login(self, user_name):
        user_details = self.iam_client.get_user(UserName=user_name)["User"]
        return user_details.get("PasswordLastUsed")
    
    def get_bucket_acl(self, bucket_name):
        return self.s3_client.get_bucket_acl(Bucket=bucket_name)
    
    def get_bucket_encryption(self, bucket_name):
        return self.s3_client.get_bucket_encryption(Bucket=bucket_name)
    
    def get_bucket_logging(self, bucket_name):
        return self.s3_client.get_bucket_logging(Bucket=bucket_name)
    
    def get_trail_status(self, trail_name):
        return self.cloudtrail_client.get_trail_status(Name=trail_name)
    
    def get_log_streams(self, log_group_name, instance_id):
        return self.logs_client.describe_log_streams(logGroupName=log_group_name, logStreamNamePrefix=instance_id).get("logStreams", [])
    
    def get_log_groups_prefix(self, log_group_prefix):
        return self.logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix).get("logGroups", [])
    
    def get_backup_selections(self, plan_id):
        return self.backup_client.list_backup_selections(BackupPlanId=plan_id).get("BackupSelectionsList", [])

    def check_unused_access_keys(self, user_name, days_threshold):
        access_keys = self.iam_client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
        unused_keys = []
        for key in access_keys:
            last_used_info = self.iam_client.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
            last_used_date = last_used_info.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            if last_used_date:
                last_used_date = last_used_date.replace(tzinfo=None)
                if (datetime.utcnow() - last_used_date).days > days_threshold:
                    unused_keys.append(key["AccessKeyId"])
        return unused_keys

    def check_password_policy(self):
        try:
            policy = self.get_account_password_policy()
            return {
                "min_length": policy.get("MinimumPasswordLength", 0),
                "require_uppercase": policy.get("RequireUppercaseCharacters", False),
                "require_lowercase": policy.get("RequireLowercaseCharacters", False),
                "require_numbers": policy.get("RequireNumbers", False),
                "require_symbols": policy.get("RequireSymbols", False),
                "max_age": policy.get("MaxPasswordAge", 0),
                "password_reuse": policy.get("PasswordReusePrevention", 0)
            }
        except Exception as e:
            return None
    
    @staticmethod
    def _is_any_port_allowed(rule):
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is None or to_port is None:
            return True  # 포트 범위가 설정되지 않음
        if from_port == 0 and to_port == 65535:
            return True  # 0-65535 모든 포트를 허용
        return False
    
    @staticmethod
    def _is_all_traffic_allowed(entry):
        protocol = entry.get("Protocol")
        rule_action = entry.get("RuleAction")
        cidr_block = entry.get("CidrBlock", entry.get("Ipv6CidrBlock"))

        # 모든 트래픽 허용 조건:
        return (
            protocol == "-1"  # 모든 프로토콜
            and rule_action == "allow"  # 허용
            and (cidr_block == "0.0.0.0/0" or cidr_block == "::/0")  # 모든 IP 허용
        )
    
    @staticmethod
    def _has_unnecessary_policy(rule):
        ip_ranges = rule.get("IpRanges", [])
        ipv6_ranges = rule.get("Ipv6Ranges", [])

        # IPv4 및 IPv6 범위 확인
        for ip_range in ip_ranges + ipv6_ranges:
            cidr = ip_range.get("CidrIp") or ip_range.get("CidrIpv6")
            if cidr == "0.0.0.0/0" or cidr == "::/0":
                # 모든 IP 허용 여부 확인
                return True
        return False
    
    @staticmethod
    def _get_nacl_name(tags):
        for tag in tags:
            if tag["Key"] == "Name":
                return tag["Value"]
        return "Unnamed NACL"
    
    @staticmethod
    def _get_route_table_name(tags):
        for tag in tags:
            if tag["Key"] == "Name":
                return tag["Value"]
        return "Unnamed Route Table"
    
    @staticmethod
    def _get_resource_name(tags):
        for tag in tags:
            if tag["Key"] == "Name":
                return tag["Value"]
        return "Unnamed Resource"
    
    @staticmethod
    def _get_associated_subnets(associations):
        return [assoc["SubnetId"] for assoc in associations if assoc.get("SubnetId")]

    @staticmethod
    def _get_instance_name(tags):
        for tag in tags:
            if tag["Key"] == "Name":
                return tag["Value"]
        return "Unnamed Instance"
    
    def _get_public_access_block(self, bucket_name):
        try:
            response = self.s3_client.get_bucket_public_access_block(Bucket=bucket_name)
            return response["PublicAccessBlockConfiguration"]
        except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            # 퍼블릭 액세스 차단 설정이 없는 경우
            return None
        
    @staticmethod
    def _get_volume_name(tags):
        for tag in tags:
            if tag["Key"] == "Name":
                return tag["Value"]
        return "Unnamed Volume"
    

    def _check_policies(self, policies_to_check):
        evidence = []

        # IAM 사용자 확인
        users = self.get_iam_users()
        for user in users:
            user_name = user["UserName"]
            policies = self.get_user_policies(user_name)

            for service, policy_name in policies_to_check.items():
                if any(policy["PolicyName"] == policy_name for policy in policies):
                    evidence.append({"사용자명": user_name, "서비스": service, "정책": policy_name})

        # IAM 그룹 확인
        groups = self.get_iam_groups()
        for group in groups:
            group_name = group["GroupName"]
            policies = self.get_group_policies(group_name)

            for service, policy_name in policies_to_check.items():
                if any(policy["PolicyName"] == policy_name for policy in policies):
                    evidence.append({"그룹명": group_name, "서비스": service, "정책": policy_name})

        return evidence
    
    
    def evaluate_result(self, evidence, weak_message, success_message):
        if evidence:
            return {"weak": True, "message": weak_message, "evidence": evidence}
        return {"weak": False, "message": success_message, "evidence": ""}