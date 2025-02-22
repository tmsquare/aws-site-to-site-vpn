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

        network = {
            "name": vpc_name,
            "auto_create_subnetworks": False,
        }
        
        try:
            operation = self.vpc_client.insert(
                project=project,
                network_resource=network
            )
            operation.result()
            print(f"VPC {vpc_name} created successfully")
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
        
        for vm in self.config['instances']['vms']:
            if self.resource_exists(self.instance_client, 'get',
                                  project=project,
                                  zone=zone,
                                  instance=vm['name']):
                print(f"Instance {vm['name']} already exists, skipping creation")
                # Get IP of existing instance
                instance = self.instance_client.get(
                    project=project,
                    zone=zone,
                    instance=vm['name']
                )
                instance_ips[vm['name']] = instance.network_interfaces[0].network_i_p
                continue

            instance_config = {
                "name": vm['name'],
                "machine_type": f"zones/{zone}/machineTypes/{self.config['instances']['machine_type']}",
                "network_interfaces": [{
                    "network": f"projects/{project}/global/networks/{self.config['network']['vpc_name']}",
                    "subnetwork": f"projects/{project}/regions/{self.config['network']['region']}/subnetworks/{self.config['network']['subnet']['name']}"
                }],
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
            
            try:
                operation = self.instance_client.insert(
                    project=project,
                    zone=zone,
                    instance_resource=instance_config
                )
                operation.result()
                print(f"Instance {vm['name']} created successfully")
                
                # Get instance IP
                instance = self.instance_client.get(
                    project=project,
                    zone=zone,
                    instance=vm['name']
                )
                instance_ips[vm['name']] = instance.network_interfaces[0].network_i_p
            except Exception as e:
                print(f"Error creating instance {vm['name']}: {str(e)}")
        
        # Update config file with IPs if we have any
        if instance_ips:
            self.config['output']['instance_ips'].update(instance_ips)
            with open(self.config_file, 'w') as file:
                yaml.dump(self.config, file)
            print("Updated configuration file with instance IPs")

    def destroy_environment(self):
        # Delete instances
        for vm in self.config['instances']['vms']:
            try:
                operation = self.instance_client.delete(
                    project=self.config['project']['id'],
                    zone=self.config['network']['zone'],
                    instance=vm['name']
                )
                operation.result()
            except Exception as e:
                print(f"Error deleting instance {vm['name']}: {str(e)}")

        # Delete firewall rules
        rules = ["allow-ssh-tunnel", "allow-web-traffic"]
        for rule in rules:
            try:
                operation = self.firewall_client.delete(
                    project=self.config['project']['id'],
                    firewall=rule
                )
                operation.result()
            except Exception as e:
                print(f"Error deleting firewall rule {rule}: {str(e)}")

        # Delete subnet
        try:
            operation = self.subnet_client.delete(
                project=self.config['project']['id'],
                region=self.config['network']['region'],
                subnetwork=self.config['network']['subnet']['name']
            )
            operation.result()
        except Exception as e:
            print(f"Error deleting subnet: {str(e)}")

        # Delete VPC
        try:
            operation = self.vpc_client.delete(
                project=self.config['project']['id'],
                network=self.config['network']['vpc_name']
            )
            operation.result()
        except Exception as e:
            print(f"Error deleting VPC: {str(e)}")

        # Clear output IPs
        self.config['output']['instance_ips'] = {}
        with open(self.config_file, 'w') as file:
            yaml.dump(self.config, file)


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
            print("\nEnvironment setup completed!")
            print("Check config.yaml for instance IPs")
        except Exception as e:
            print(f"\nError during environment creation: {str(e)}")
            print("Some resources may have been created. You can:")
            print("1. Fix the error and run again (existing resources will be skipped)")
            print("2. Run with 'destroy' argument to clean up all resources and start fresh")

if __name__ == "__main__":
    main()