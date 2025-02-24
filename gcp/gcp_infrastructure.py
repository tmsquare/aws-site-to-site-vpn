import yaml
import os
from google.cloud import compute_v1
from google.oauth2 import service_account
from google.api_core import exceptions
import time

class GCPInfraManager:
    def __init__(self, config_file):
        self.config_file = config_file
        self.load_config()
        self.setup_credentials()
        self.setup_clients()

    def load_config(self):
        with open(self.config_file, 'r') as file:
            self.config = yaml.safe_load(file)

    def setup_credentials(self):
        credentials = service_account.Credentials.from_service_account_file(
            self.config['project']['credentials_file'],
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )
        self.credentials = credentials

    def setup_clients(self):
        self.vpc_client = compute_v1.NetworksClient(credentials=self.credentials)
        self.subnet_client = compute_v1.SubnetworksClient(credentials=self.credentials)
        self.firewall_client = compute_v1.FirewallsClient(credentials=self.credentials)
        self.instance_client = compute_v1.InstancesClient(credentials=self.credentials)
        self.router_client = compute_v1.RoutersClient(credentials=self.credentials)
        self.route_client = compute_v1.RoutesClient(credentials=self.credentials)

    def create_cloud_router(self): # Equivalent of the AWS Virtual Private Gateway
        project = self.config['project']['id']
        region = self.config['network']['region']
        router_name = f"{self.config['network']['vpc_name']}-router"
        
        router_config = compute_v1.Router()
        router_config.name = router_name
        router_config.network = f"projects/{project}/global/networks/{self.config['network']['vpc_name']}"
        
        # Configure NAT: Like the AWS Route Table
        nat = compute_v1.RouterNat()
        nat.name = f"{self.config['network']['vpc_name']}-nat"
        nat.nat_ip_allocate_option = "AUTO_ONLY"
        nat.source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
        
        router_config.nats = [nat]
        
        try:
            if not self.resource_exists(self.router_client, 'get',
                                    project=project,
                                    region=region,
                                    router=router_name):
                operation = self.router_client.insert(
                    project=project,
                    region=region,
                    router_resource=router_config
                )
                operation.result()
                print(f"Cloud Router and NAT created successfully")
            else:
                print(f"Cloud Router already exists, skipping creation")
                
            return router_name
        except Exception as e:
            print(f"Error creating Cloud Router and NAT: {str(e)}")
            raise

    def create_custom_routes(self):
        """Create custom routes for Cloudflare WARP traffic"""
        project = self.config['project']['id']
        next_hop_instance = str(f"projects/{self.config['project']['id']}/zones/{self.config['network']['zone']}/instances/tunnel")
        
        route = compute_v1.Route()
        route.name = "warp-return-route"
        route.network = f"projects/{project}/global/networks/{self.config['network']['vpc_name']}"
        route.dest_range = f"{self.config['network']['warp_cidr']}"  # WARP IP range
        route.next_hop_instance = next_hop_instance
        route.priority = 800
        
        try:
            operation = self.route_client.insert(
                project=project,
                route_resource=route
            )
            operation.result()
            print(f"Created custom route for WARP traffic")
        except Exception as e:
            print(f"Error creating custom route: {str(e)}")

    def resource_exists(self, client, method, **kwargs):
        try:
            getattr(client, method)(**kwargs)
            return True
        except exceptions.NotFound:
            return False
        except Exception as e:
            print(f"Error checking resource: {str(e)}")
            return False

    def create_vpc(self):
        project = self.config['project']['id']
        vpc_name = self.config['network']['vpc_name']

        if self.resource_exists(self.vpc_client, 'get', 
                              project=project, 
                              network=vpc_name):
            print(f"VPC {vpc_name} already exists, skipping creation")
            return

        network = compute_v1.Network()
        network.name = vpc_name
        network.auto_create_subnetworks = False
        network.routing_config = compute_v1.NetworkRoutingConfig()
        network.routing_config.routing_mode = "GLOBAL"
            
        try:
            operation = self.vpc_client.insert(
                project=project,
                network_resource=network
            )
            operation.result()
            print(f"VPC {vpc_name} created successfully")

            # Create Cloud Router with NAT after VPC
            self.create_cloud_router()
        except Exception as e:
            print(f"Error creating VPC: {str(e)}")
            raise

    def create_subnet(self):
        project = self.config['project']['id']
        region = self.config['network']['region']
        subnet_name = self.config['network']['subnet']['name']

        if self.resource_exists(self.subnet_client, 'get',
                              project=project,
                              region=region,
                              subnetwork=subnet_name):
            print(f"Subnet {subnet_name} already exists, skipping creation")
            return

        subnet = {
            "name": subnet_name,
            "ip_cidr_range": self.config['network']['subnet']['cidr_range'],
            "network": f"projects/{project}/global/networks/{self.config['network']['vpc_name']}",
            "region": region
        }
        
        try:
            operation = self.subnet_client.insert(
                project=project,
                region=region,
                subnetwork_resource=subnet
            )
            operation.result()
            print(f"Subnet {subnet_name} created successfully")
        except Exception as e:
            print(f"Error creating subnet: {str(e)}")
            raise

    def create_firewall_rules(self):
        project = self.config['project']['id']
        rules = [
            {
                "name": "allow-ssh-tunnel",
                "network": f"projects/{project}/global/networks/{self.config['network']['vpc_name']}",
                "allowed": [{"I_p_protocol": "tcp", "ports": ["22"]}],
                "target_tags": ["tunnel"],
                "source_ranges": ["0.0.0.0/0"]
            },
            {
                "name": "allow-web-traffic",
                "network": f"projects/{project}/global/networks/{self.config['network']['vpc_name']}",
                "allowed": [
                    {"I_p_protocol": "tcp", "ports": ["80", "443"]},
                    {"I_p_protocol": "icmp"}
                ],
                "target_tags": ["web-server"],
                "source_ranges": ["0.0.0.0/0"]
            },
            {
                "name": "allow-internal",
                "network": f"projects/{project}/global/networks/{self.config['network']['vpc_name']}",
                "allowed": [
                    {"I_p_protocol": "tcp"},
                    {"I_p_protocol": "udp"},
                    {"I_p_protocol": "icmp"}
                ],
                "source_ranges": ["172.16.0.0/24"]  # Allow all internal traffic within subnet
            }
        ]
        
        for rule in rules:
            if self.resource_exists(self.firewall_client, 'get',
                                  project=project,
                                  firewall=rule["name"]):
                print(f"Firewall rule {rule['name']} already exists, skipping creation")
                continue

            try:
                operation = self.firewall_client.insert(
                    project=project,
                    firewall_resource=rule
                )
                operation.result()
                print(f"Firewall rule {rule['name']} created successfully")
            except Exception as e:
                print(f"Error creating firewall rule {rule['name']}: {str(e)}")

    def create_instances(self):
        project = self.config['project']['id']
        zone = self.config['network']['zone']
        instance_ips = {}
        tunnel_startup_script = f"""#!/bin/bash
        echo 1 > /proc/sys/net/ipv4/ip_forward
        sysctl -w net.ipv4.ip_forward=1
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        apt update -y && apt install -y iptables-persistent
        netfilter-persistent save
        """
        
        for vm in self.config['instances']['vms']:
            if self.resource_exists(self.instance_client, 'get',
                                  project=project,
                                  zone=zone,
                                  instance=vm['name']):
                print(f"Instance {vm['name']} already exists, skipping creation")
                instance = self.instance_client.get(
                    project=project,
                    zone=zone,
                    instance=vm['name']
                )
                instance_ips[vm['name']] = instance.network_interfaces[0].network_i_p
                continue

            # Modified network interface configuration to include external IP
            network_interface = {
                "network": f"projects/{project}/global/networks/{self.config['network']['vpc_name']}",
                "subnetwork": f"projects/{project}/regions/{self.config['network']['region']}/subnetworks/{self.config['network']['subnet']['name']}",
                # Add access config to get external IP
                "access_configs": [
                    {
                        "name": "External NAT",
                        "type": "ONE_TO_ONE_NAT"
                    }
                ]
            }

            instance_config = {
                "name": vm['name'],
                "machine_type": f"zones/{zone}/machineTypes/{self.config['instances']['machine_type']}",
                "network_interfaces": [network_interface],
                "disks": [{
                    "boot": True,
                    "auto_delete": True,
                    "initialize_params": {
                        "source_image": self.config['instances']['image']
                    }
                }],
                "tags": {
                    "items": ["tunnel" if vm['type'] == "tunnel" else "web-server"]
                }
            }
            tunnel_instance_config = {
                "name": vm['name'],
                "can_ip_forward": True,  # ✅ Enables IP forwarding
                "machine_type": f"zones/{zone}/machineTypes/{self.config['instances']['machine_type']}",
                "network_interfaces": [network_interface],
                "disks": [{
                    "boot": True,
                    "auto_delete": True,
                    "initialize_params": {
                        "source_image": self.config['instances']['image']
                    }
                }],
                "tags": {
                    "items": ["tunnel" if vm['type'] == "tunnel" else "web-server"]
                },
                #"metadata": {
                #    "items": [
                #       {
                #            "key": "startup_script", 
                #            "value": tunnel_startup_script
                #        }
                #    ]
                #}
            }
            
            try:
                if vm['type'] == "tunnel":
                    operation = self.instance_client.insert(
                        project=project,
                        zone=zone,
                        instance_resource=tunnel_instance_config
                    )
                else:
                    operation = self.instance_client.insert(
                        project=project,
                        zone=zone,
                        instance_resource=instance_config
                    )     
                operation.result()
                print(f"Instance {vm['name']} created successfully")
                
                # Get instance details including both internal and external IPs
                instance = self.instance_client.get(
                    project=project,
                    zone=zone,
                    instance=vm['name']
                )
                instance_ips[vm['name']] = {
                    'internal_ip': instance.network_interfaces[0].network_i_p
                }
                print(f"Instance {vm['name']} IP - Internal: {instance_ips[vm['name']]['internal_ip']}")
            except Exception as e:
                print(f"Error creating instance {vm['name']}: {str(e)}")
        
        # Update config file with IPs
        if instance_ips:
            self.config['output']['instance_ips'] = instance_ips
            with open(self.config_file, 'w') as file:
                yaml.dump(self.config, file)
            print("Updated configuration file with instance IPs")

    def destroy_environment(self):
        project = self.config['project']['id']
        region = self.config['network']['region']
        zone = self.config['network']['zone']
        vpc_name = self.config['network']['vpc_name']
        router_name = f"{self.config['network']['vpc_name']}-router"
        route_name = "warp-return-route"

        # Keep track of operations to wait for
        operations = []

        print("Starting environment destruction...")

        # 1. Delete instances first
        print("Deleting instances...")
        for vm in self.config['instances']['vms']:
            try:
                if self.resource_exists(self.instance_client, 'get',
                                    project=project,
                                    zone=zone,
                                    instance=vm['name']):
                    operation = self.instance_client.delete(
                        project=project,
                        zone=zone,
                        instance=vm['name']
                    )
                    operations.append(('instance', operation))
                    print(f"Deletion initiated for instance {vm['name']}")
            except Exception as e:
                print(f"Error deleting instance {vm['name']}: {str(e)}")

        # Wait for all instance deletions to complete
        for res_type, operation in operations:
            try:
                operation.result()
            except Exception as e:
                print(f"Error waiting for {res_type} deletion: {str(e)}")
        operations.clear()

        # 2.1 Delete Router
        print("Deleting Cloud Router...")
        try:
            if self.resource_exists(self.router_client, 'get',
                                project=project,
                                region=region,
                                router=router_name):
                operation = self.router_client.delete(
                    project=project,
                    region=region,
                    router=router_name
                )
                operation.result()
                print("Cloud Router deleted successfully")
        except Exception as e:
            print(f"Error deleting Cloud Router: {str(e)}")

        # 2.2 Delete NAT (Route)
        print("Deleting WARP Route...")
        try:
            if self.resource_exists(self.route_client, 'get',
                                project=project,
                                route=route_name):
                operation = self.route_client.delete(
                    project=project,
                    route=route_name
                )
                operation.result()
                print("WARP Route deleted successfully")
        except Exception as e:
            print(f"Error deleting WARP Route: {str(e)}")

        # 3. Delete firewall rules
        print("Deleting firewall rules...")
        firewall_rules = ["allow-ssh-tunnel", "allow-web-traffic", "allow-internal"]
        for rule in firewall_rules:
            try:
                if self.resource_exists(self.firewall_client, 'get',
                                    project=project,
                                    firewall=rule):
                    operation = self.firewall_client.delete(
                        project=project,
                        firewall=rule
                    )
                    operations.append(('firewall', operation))
                    print(f"Deletion initiated for firewall rule {rule}")
            except Exception as e:
                print(f"Error deleting firewall rule {rule}: {str(e)}")

        # Wait for all firewall deletions to complete
        for res_type, operation in operations:
            try:
                operation.result()
            except Exception as e:
                print(f"Error waiting for {res_type} deletion: {str(e)}")
        operations.clear()

        # 4. Delete subnet
        print("Deleting subnet...")
        try:
            if self.resource_exists(self.subnet_client, 'get',
                                project=project,
                                region=region,
                                subnetwork=self.config['network']['subnet']['name']):
                operation = self.subnet_client.delete(
                    project=project,
                    region=region,
                    subnetwork=self.config['network']['subnet']['name']
                )
                operation.result()
                print(f"Subnet {self.config['network']['subnet']['name']} deleted")
        except Exception as e:
            print(f"Error deleting subnet: {str(e)}")

        # 5. Delete VPC (only after all other resources are deleted)
        print("Deleting VPC...")
        try:
            if self.resource_exists(self.vpc_client, 'get',
                                project=project,
                                network=vpc_name):
                # Check for any remaining firewall rules
                remaining_firewalls = self.firewall_client.list(project=project)
                for firewall in remaining_firewalls:
                    if vpc_name in firewall.network:
                        print(f"Deleting remaining firewall rule: {firewall.name}")
                        operation = self.firewall_client.delete(
                            project=project,
                            firewall=firewall.name
                        )
                        operation.result()

                # Now try to delete the VPC
                operation = self.vpc_client.delete(
                    project=project,
                    network=vpc_name
                )
                operation.result()
                print(f"VPC {vpc_name} deleted")
        except Exception as e:
            print(f"Error deleting VPC: {str(e)}")

        # Clear output IPs
        self.config['output']['instance_ips'] = {}
        with open(self.config_file, 'w') as file:
            yaml.dump(self.config, file)
        
        print("Environment destruction completed!")


def main():
    manager = GCPInfraManager('gcp_config.yaml')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'destroy':
        print("Destroying environment...")
        manager.destroy_environment()
        print("Environment destroyed successfully")
    else:
        print("Creating environment...")
        try:
            manager.create_vpc()
            manager.create_subnet()
            manager.create_firewall_rules()
            manager.create_instances()
            manager.create_custom_routes()
            print("\nEnvironment setup completed!")
            print("Check config.yaml for instance IPs")
        except Exception as e:
            print(f"\nError during environment creation: {str(e)}")
            print("Some resources may have been created. You can:")
            print("1. Fix the error and run again (existing resources will be skipped)")
            print("2. Run with 'destroy' argument to clean up all resources and start fresh")

if __name__ == "__main__":
    main()
