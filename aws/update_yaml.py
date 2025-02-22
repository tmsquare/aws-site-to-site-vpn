# update_outputs.py
import boto3
import yaml
import json
import sys
import os
import requests
from cloudflare import Cloudflare


def get_stack_outputs(stack_name, region):
    """Get the outputs from a CloudFormation stack"""
    cf_client = boto3.client('ec2', region_name=region)
    cfn_client = boto3.client('cloudformation', region_name=region)
    
    try:
        response = cfn_client.describe_stacks(StackName=stack_name)
        outputs = {output['OutputKey']: output['OutputValue'] 
                  for output in response['Stacks'][0]['Outputs']}
        
        vpn_response = cf_client.describe_vpn_connections(
            VpnConnectionIds=[outputs['VPNConnectionId']]
        )
        
        if vpn_response['VpnConnections']:
            tunnels = vpn_response['VpnConnections'][0]['VgwTelemetry']
            outputs['Tunnel1OutsideIP'] = tunnels[0]['OutsideIpAddress']
            outputs['Tunnel2OutsideIP'] = tunnels[1]['OutsideIpAddress']
        
        return outputs
    
    except Exception as e:
        print(f"Error getting stack outputs: {str(e)}")
        return None

def update_yaml_file(outputs):
    try:
        with open('config.yaml', 'r') as file:
            config = yaml.safe_load(file)
        
        config['output'] = {
            'VpcId': outputs['VpcId'],
            'SubnetId': outputs['SubnetId'],
            'CustomerGatewayId': outputs['CustomerGatewayId'],
            'VPNGatewayId': outputs['VPNGatewayId'],
            'VPNConnectionId': outputs['VPNConnectionId'],
            'EC2InstanceId': outputs['EC2InstanceId'],
            'EC2PublicIP': outputs['EC2PublicIP'],
            'EC2PrivateIP': outputs['EC2PrivateIP']
        }
        
        if 'vpn' not in config:
            config['vpn'] = {}
        if 'tunnel1' not in config['vpn']:
            config['vpn']['tunnel1'] = {}
        if 'tunnel2' not in config['vpn']:
            config['vpn']['tunnel2'] = {}
            
        config['vpn']['tunnel1']['outside_ip'] = outputs['Tunnel1OutsideIP']
        config['vpn']['tunnel2']['outside_ip'] = outputs['Tunnel2OutsideIP']
        
        with open('config.yaml', 'w') as file:
            yaml.dump(config, file, default_flow_style=False, sort_keys=False)
            
        print("Successfully updated config.yaml with actual values")
        
    except Exception as e:
        print(f"Error updating YAML file: {str(e)}")

if __name__ == "__main__":
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)
        
    stack_name = "VpnInfrastructureStack"
    region = config['aws']['region']
    
    outputs = get_stack_outputs(stack_name, region)
    if outputs:
        update_yaml_file(outputs)
