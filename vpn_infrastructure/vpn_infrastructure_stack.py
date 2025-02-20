import yaml
import boto3
import json
from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    CfnOutput,
    aws_iam as iam
)
from constructs import Construct

class VpnInfrastructureStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Load configuration from YAML file
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)

        # Create VPC
        self.vpc = ec2.Vpc(
            self, "cf-vpc",
            vpc_name="cf-vpc",
            ip_addresses=ec2.IpAddresses.cidr(config['vpc']['cidr']),
            max_azs=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="cf-subnet",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                )
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )

        # Get reference to the subnet
        self.subnet = self.vpc.public_subnets[0]

        # Create Customer Gateway
        self.customer_gateway = ec2.CfnCustomerGateway(
            self, "cf-customer-gateway",
            bgp_asn=65000,
            ip_address=config['vpn']['magic_wan_ip'],
            type="ipsec.1",
            tags=[{"key": "Name", "value": "cf-customer-gateway"}]
        )

        # Create Virtual Private Gateway
        self.vpn_gateway = ec2.CfnVPNGateway(
            self, "cf-vpn-gateway",
            type="ipsec.1",
            tags=[{"key": "Name", "value": "cf-vpn-gateway"}]
        )

        # Attach VPN Gateway to VPC
        self.vpn_gateway_attachment = ec2.CfnVPCGatewayAttachment(
            self, "VPNGatewayAttachment",
            vpc_id=self.vpc.vpc_id,
            vpn_gateway_id=self.vpn_gateway.ref
        )

        # Enable route propagation
        self.route_table = self.subnet.route_table
        ec2.CfnVPNGatewayRoutePropagation(
            self, "RoutePropagation",
            route_table_ids=[self.route_table.route_table_id],
            vpn_gateway_id=self.vpn_gateway.ref
        ).add_dependency(self.vpn_gateway_attachment)

        # Create VPN Connection
        self.vpn_connection = ec2.CfnVPNConnection(
            self, "cf-vpn-connection",
            customer_gateway_id=self.customer_gateway.ref,
            type="ipsec.1",
            vpn_gateway_id=self.vpn_gateway.ref,
            static_routes_only=True,
            vpn_tunnel_options_specifications=[
                {
                    "preSharedKey": config['vpn']['tunnel1']['pre_shared_key'],
                    "tunnelInsideCidr": config['vpn']['tunnel1']['inside_cidr'],
                    "phase1EncryptionAlgorithms": [{"value": "AES256-GCM-16"}],
                    "phase2EncryptionAlgorithms": [{"value": "AES256-GCM-16"}],
                    "phase1IntegrityAlgorithms": [{"value": "SHA2-256"}],
                    "phase2IntegrityAlgorithms": [{"value": "SHA2-256"}],
                    "phase1DHGroupNumbers": [{"value": 14}],
                    "phase2DHGroupNumbers": [{"value": 14}],
                    "ikeVersions": [{"value": "ikev2"}],
                    "startupAction": "start"
                },
                {
                    "preSharedKey": config['vpn']['tunnel2']['pre_shared_key'],
                    "tunnelInsideCidr": config['vpn']['tunnel2']['inside_cidr'],
                    "phase1EncryptionAlgorithms": [{"value": "AES256-GCM-16"}],
                    "phase2EncryptionAlgorithms": [{"value": "AES256-GCM-16"}],
                    "phase1IntegrityAlgorithms": [{"value": "SHA2-256"}],
                    "phase2IntegrityAlgorithms": [{"value": "SHA2-256"}],
                    "phase1DHGroupNumbers": [{"value": 14}],
                    "phase2DHGroupNumbers": [{"value": 14}],
                    "ikeVersions": [{"value": "ikev2"}],
                    "startupAction": "start"
                }
            ],
            tags=[{"key": "Name", "value": "cf-vpn-connection"}]
        )

        # Add static route for VPN connection
        ec2.CfnVPNConnectionRoute(
            self, "VPNConnectionRoute",
            destination_cidr_block="0.0.0.0/0",
            vpn_connection_id=self.vpn_connection.ref
        )

        # Create EC2 Instance
        # Get the latest Debian AMI
        debian_ami = ec2.MachineImage.lookup(
            name="debian-11-amd64-*",
            owners=["136693071363"],  # Debian's AWS account
            windows=False
        )

        # Create security group for EC2
        security_group = ec2.SecurityGroup(
            self, "EC2SecurityGroup",
            vpc=self.vpc,
            description="Security group for Debian EC2 instance",
            allow_all_outbound=True
        )
        
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(22),
            "Allow SSH access"
        )
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(80),
            "Allow HTTP access"
        )
        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.all_icmp(),
            "Allow ICMP access"
        )

        # Create EC2 instance
        self.instance = ec2.Instance(
            self, "DebianInstance",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            instance_type=ec2.InstanceType(config['ec2']['instance_type']),
            machine_image=debian_ami,
            security_group=security_group,
            block_devices=[
                ec2.BlockDevice(
                    device_name="/dev/xvda",
                    volume=ec2.BlockDeviceVolume.ebs(
                        volume_size=config['ec2']['volume_size'],
                        volume_type=ec2.EbsDeviceVolumeType.GP2
                    )
                )
            ]
        )

        # Add CloudFormation outputs
        CfnOutput(self, "VpcId", value=self.vpc.vpc_id)
        CfnOutput(self, "SubnetId", value=self.subnet.subnet_id)
        CfnOutput(self, "CustomerGatewayId", value=self.customer_gateway.ref)
        CfnOutput(self, "VPNGatewayId", value=self.vpn_gateway.ref)
        CfnOutput(self, "VPNConnectionId", value=self.vpn_connection.ref)
        CfnOutput(self, "EC2InstanceId", value=self.instance.instance_id)
        CfnOutput(self, "EC2PublicIP", value=self.instance.instance_public_ip)
        CfnOutput(self, "EC2PrivateIP", value=self.instance.instance_private_ip)


