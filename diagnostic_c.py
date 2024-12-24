from aws_api import AWSAPI


class DiagnosticC:
    def __init__(self, credentials_file):
        self.aws_api = AWSAPI(credentials_file)

    # 보안 그룹 인/아웃바운드 설정 관리 - 자동화
    # 완성
    def C01(self):
        evidence = []
        security_groups = self.aws_api.get_security_groups()
        
        for sg in security_groups:
            sg_name = sg["GroupName"]
            sg_id = sg["GroupId"]

            # 인바운드 규칙 확인
            for rule in sg.get("IpPermissions", []):
                if self.aws_api._is_any_port_allowed(rule):
                    evidence.append({"Type": "Inbound", "SecurityGroupName": sg_name, "SecurityGroupId": sg_id, "Rule": rule})

            # 아웃바운드 규칙 확인
            for rule in sg.get("IpPermissionsEgress", []):
                if self.aws_api._is_any_port_allowed(rule):
                    evidence.append({"Type": "Outbound", "SecurityGroupName": sg_name, "SecurityGroupId": sg_id, "Rule": rule})
        
        return self.aws_api.evaluate_result(evidence, "보안 그룹 내 포트 전체 허용 정책이 존재합니다.", "양호합니다.")

    # 보안 그룹 인/아웃바운드 불필요 정책 관리 - 일부 자동화
    # 완성 (현재는 모든 IP 허용으로 한정 탐지, 상황에 맞게 수동 조사 필요)
    def C02(self):
        evidence = []
        security_groups = self.aws_api.get_security_groups()
        
        
        for sg in security_groups:
            sg_name = sg["GroupName"]
            sg_id = sg["GroupId"]

            # 인바운드 규칙 확인
            for rule in sg.get("IpPermissions", []):
                if self.aws_api._has_unnecessary_policy(rule):
                    evidence.append({"Type": "Inbound", "SecurityGroupName": sg_name, "SecurityGroupId": sg_id, "Rule": rule})

            # 아웃바운드 규칙 확인
            for rule in sg.get("IpPermissionsEgress", []):
                if self.aws_api._has_unnecessary_policy(rule):
                    evidence.append({"Type": "Outbound", "SecurityGroupName": sg_name, "SecurityGroupId": sg_id, "Rule": rule})

        return self.aws_api.evaluate_result(evidence, "보안 그룹 내 불필요한 정책이 존재합니다.", "양호합니다.")

    # 네트워크 인/아웃바운드 트래픽 정책 관리 - 자동화
    # 완성
    def C03(self):
        evidence = []
        nacls = self.aws_api.get_network_acls()
        
        for nacl in nacls:
            nacl_id = nacl["NetworkAclId"]
            nacl_name = self.aws_api._get_nacl_name(nacl.get("Tags", []))

            # 인바운드 규칙 확인
            for entry in nacl.get("Entries", []):
                if not entry.get("Egress", False) and self.aws_api._is_all_traffic_allowed(entry):
                    evidence.append({"Type": "Inbound", "NetworkAclName": nacl_name, "NetworkAclId": nacl_id, "Rule": entry})

            # 아웃바운드 규칙 확인
            for entry in nacl.get("Entries", []):
                if entry.get("Egress", False) and self.aws_api._is_all_traffic_allowed(entry):
                    evidence.append({"Type": "Outbound", "NetworkAclName": nacl_name, "NetworkAclId": nacl_id, "Rule": entry})

        return self.aws_api.evaluate_result(evidence, "네트워크 ACL 내 모든 트래픽 허용이 존재합니다.", "양호합니다.")

    # 라우팅 테이블 정책 관리 - 자동화
    # 완성
    def C04(self):
        evidence = []
        route_tables = self.aws_api.get_route_tables()

        # 서비스별 올바른 타깃 설정 예시
        valid_targets = {
            "InternetGateway": "igw-",  # 인터넷 게이트웨이
            "TransitGateway": "tgw-",  # 트랜싯 게이트웨이
            "VirtualPrivateGateway": "vgw-",  # 가상 프라이빗 게이트웨이
            "NATGateway": "nat-",  # NAT 게이트웨이
            "VpcPeeringConnection": "pcx-",  # VPC 피어링 연결
        }

        for table in route_tables:
            table_id = table["RouteTableId"]
            table_name = self.aws_api._get_route_table_name(table.get("Tags", []))

            for route in table.get("Routes", []):
                destination_cidr = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
                target_id = route.get("GatewayId") or route.get("TransitGatewayId") or route.get("NatGatewayId") or route.get("VpcPeeringConnectionId")

                # Any 정책 확인
                if destination_cidr in ["0.0.0.0/0", "::/0"]:
                    evidence.append({"Type": "AnyPolicy", "RouteTableName": table_name, "RouteTableId": table_id, "Route": route})

                # 서비스 타깃 검증
                if target_id and not any(target_id.startswith(prefix) for prefix in valid_targets.values()):
                    evidence.append({"Type": "InvalidTargets", "RouteTableName": table_name, "RouteTableId": table_id, "Route": route, "TargetId": target_id})

        return self.aws_api.evaluate_result(evidence, "라우팅 테이블 내 Any 정책이 설정되어 있거나 서비스 타깃 별 설정 미흡합니다.", "양호합니다.")

    # 인터넷 게이트웨이 연결 관리 - 자동화
    # 완성
    def C05(self):
        evidence = []
        # 인터넷 게이트웨이 정보 가져오기
        internet_gateways = self.aws_api.get_internet_gateways()
        nat_gateways = self.aws_api.get_nat_gateways()


        for igw in internet_gateways:
            igw_id = igw["InternetGatewayId"]
            igw_name = self.aws_api._get_resource_name(igw.get("Tags", []))

            # IGW에 연결된 VPC 가져오기
            attachments = igw.get("Attachments", [])
            attached_vpc_ids = [attachment["VpcId"] for attachment in attachments if attachment["State"] == "available"]

            for nat_gw in nat_gateways:
                nat_gw_id = nat_gw["NatGatewayId"]
                nat_gw_name = self.aws_api._get_resource_name(nat_gw.get("Tags", []))
                nat_gw_vpc_id = nat_gw["VpcId"]

                # NAT Gateway가 IGW와 연결된 VPC에 속하는지 확인
                if nat_gw_id in attached_vpc_ids:
                    evidence.append({"InternetGatewayName": igw_name, "InternetGatewayId": igw_id, "NatGatewayName": nat_gw_name, "NatGatewayId": nat_gw_id, "VpcId": nat_gw_vpc_id})

        return self.aws_api.evaluate_result(evidence, "인터넷 게이트웨이에 불필요하게 연결된 NAT게이트웨이가 존재합니다.", "양호합니다.")

    # NAT 게이트웨이 연결 관리 - 자동화
    # 완성 (추후 NAT게이트웨이 설정 후 재검토!!!!!!!!!)
    def C06(self):
        evidence = []
        route_tables = self.aws_api.get_route_tables()
        nat_gateways = self.aws_api.get_nat_gateways()
        ec2_instances = self.aws_api.get_instances()

        # NAT 게이트웨이가 연결된 서브넷 ID 목록 수집
        nat_gateway_subnet_ids = [
            nat_gw["SubnetId"] for nat_gw in nat_gateways if nat_gw["State"] == "available"
        ]

        # 라우팅 테이블에서 NAT 게이트웨이가 설정된 서브넷 확인
        subnets_with_nat = set()
        for table in route_tables:
            for route in table.get("Routes", []):
                if route.get("NatGatewayId") in [nat["NatGatewayId"] for nat in nat_gateways]:
                    associated_subnets = self.aws_api._get_associated_subnets(table["Associations"])
                    subnets_with_nat.update(associated_subnets)

        # EC2 인스턴스가 NAT 게이트웨이에 연결되어 있는지 확인
        for reservation in ec2_instances:
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]
                subnet_id = instance["SubnetId"]
                instance_name = self.aws_api._get_instance_name(instance.get("Tags", []))

                if subnet_id not in subnets_with_nat:
                    evidence.append({"InstanceName": instance_name, "InstanceId": instance_id, "SubnetId": subnet_id})

        return self.aws_api.evaluate_result(evidence, "외부 통신이 필요한 리소스가 NAT 게이트웨이에 연결되어 있지 않습니다.", "양호합니다.")

    # S3 버킷/객체 접근 관리 - 자동화
    # 완성 (추후 S3 버킷 설정 후 재검토!!!!!!!!!)
    def C07(self):
        evidence = []
        buckets = self.aws_api.get_s3_buckets()

        for bucket in buckets:
            bucket_name = bucket["Name"]

            # 퍼블릭 액세스 차단 상태 확인
            public_access_block = self.aws_api._get_public_access_block(bucket_name)

            if not public_access_block or not public_access_block.get("BlockPublicAcls", True):
                # 퍼블릭 액세스 차단이 설정되지 않은 경우 ACL 확인
                acl = self.aws_api.get_bucket_acl(bucket_name)
                owner_id = acl["Owner"]["ID"]
                grants = acl.get("Grants", [])

                for grant in grants:
                    grantee = grant["Grantee"]
                    if grantee.get("Type") == "Group" and "AllUsers" in grantee.get("URI", ""):
                        evidence.append({"Issue": "퍼블릭 액세스 권한 허용", "BucketName": bucket_name, "PublicAccessSetting": public_access_block, "ACL": acl})
                        break

                if grantee.get("Type") == "CanonicalUser" and grantee.get("ID") != owner_id:
                    evidence.append({"Issue": "ACL을 일반 사용자에게도 부여", "BucketName": bucket_name, "PublicAccessSetting": public_access_block, "ACL": acl})
                    break
                
        return self.aws_api.evaluate_result(evidence, "S3 버킷 접근 관리가 안전하지 않습니다.", "양호합니다.")

    # 자동화
    def C08(self):
        evidence = []
        subnet_groups = self.aws_api.get_db_subnet_groups()

        for group in subnet_groups:
            group_name = group["DBSubnetGroupName"]
            subnets = group["Subnets"]
            
            # 서브넷의 가용 영역 수집
            azs = {subnet["SubnetAvailabilityZone"]["Name"] for subnet in subnets}
            extra_azs = azs - set(self.aws_api.required_azs)
            
            # 불필요한 가용 영역이 있으면 기록
            if extra_azs:
                evidence.append({"DBSubnetGroupName": group_name, "ExtraAZs": list(extra_azs), "AllAZs": list(azs)})
                
        return self.aws_api.evaluate_result(evidence, "RDS 서브넷 그룹 내 불필요한 가용 영역이 존재합니다.", "양호합니다.")
