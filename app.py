import yaml
import aws_cdk as cdk
from vpn_infrastructure.vpn_infrastructure_stack import VpnInfrastructureStack


with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

app = cdk.App()
stack = VpnInfrastructureStack(
    app, 
    "VpnInfrastructureStack",
    env=cdk.Environment(
        account = config['aws']['account_id'],  
        region = config['aws']['region']
    )
)
app.synth()
