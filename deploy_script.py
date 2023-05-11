# https://github.com/Azure/azure-sdk-for-python/issues/25990
import subprocess
import json
import stat
import os
import sys
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.subscription.operations import SubscriptionsOperations
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.identity import DefaultAzureCredential, AzureCliCredential, InteractiveBrowserCredential
# from utils import retrieve_subscription_id_for_subscription_name
from azure.storage.blob import BlobServiceClient


# default_credential = InteractiveBrowserCredential()
# sub_client = SubscriptionClient(default_credential)
# for l in sub_client.subscriptions.list():
#     print(l.id)

# logged_in_account = json.loads(subprocess.check_output('az login', shell=True).decode('utf-8'))

# SUBSCRIPTION_ID = ''
# # RESOURCE_GROUP_NAME = "bogdanTailupThesisGroup"
# # LOCATION = "westeurope"
# # VNET_NAME = "bogdanTailupThesisVnet"
# # SUBNET_NAME = "bogdanTailupThesisSubnet"
# # IP_NAME = "bogdanTailupThesisIp"
# # IP_CONFIG_NAME = "bogdanTailupThesisIpConfig"
# # PUBLIC_KEY_NAME = "bogdanTailupThesisPublicKey"
# # PRIVATE_KEY_NAME = "bogdanTailupThesisPrivateKey"
# # NSG_NAME = "bogdanTailupNSG"
# # NIC_NAME = "bogdanTailupThesisNIC"
# # VM_NAME = "bogdanTailupThesisVM"
# # USERNAME = "azureuser"
# # PASSWORD = "Btailup68@@a"
# # SECURITY_RULE_INBOUND = "bogdanTailupThesisSecurityRuleINBOUND"
# # SECURITY_RULE_OUTBOUND = "bogdanTailupThesisSecurityRuleOUTBOUND"
# # SECURITY_RULE_SSH = "bogdanTailupThesisSecurityRuleSSH"

SUBSCRIPTION_ID = sys.argv[1]
RESOURCE_GROUP_NAME = sys.argv[2]
LOCATION = sys.argv[3]
VNET_NAME = sys.argv[4]
SUBNET_NAME = sys.argv[5]
IP_NAME = sys.argv[6]
# IP_CONFIG_NAME = sys.argv[7]
# PUBLIC_KEY_NAME = sys.argv[8]
# PRIVATE_KEY_NAME = sys.argv[9]
# NSG_NAME = sys.argv[10]
# NIC_NAME = sys.argv[11]
# VM_NAME = sys.argv[12]
# USERNAME = sys.argv[13]
# PASSWORD = sys.argv[14]
# SECURITY_RULE_INBOUND = sys.argv[15]
# SECURITY_RULE_OUTBOUND = sys.argv[16]
# SECURITY_RULE_SSH = sys.argv[17]

print(SUBSCRIPTION_ID, RESOURCE_GROUP_NAME,LOCATION, VNET_NAME, SUBNET_NAME)
    #   IP_NAME, IP_CONFIG_NAME, PUBLIC_KEY_NAME, PRIVATE_KEY_NAME, NSG_NAME, NIC_NAME,
    #   VM_NAME, USERNAME, PASSWORD,SECURITY_RULE_INBOUND, SECURITY_RULE_OUTBOUND, SECURITY_RULE_SSH)
# interactive_credential = InteractiveBrowserCredential()
# dummy_sub_client = SubscriptionClient(interactive_credential)
# for s in dummy_sub_client.subscriptions.list():
#     print(s)

# default_credential = AzureCliCredential()
# sub_client = SubscriptionClient(default_credential)
#
# for s in sub_client.subscriptions.list():
#     if s.subscription_id != '':
#         SUBSCRIPTION_ID = s.subscription_id
#     break
#
#
# resource_management_client = ResourceManagementClient(default_credential, SUBSCRIPTION_ID)
#
# # Create resource group
#
# def create_resource_group(resource_management_client: ResourceManagementClient):
#     next_resource_group_number = 0
#     for resource_group in resource_management_client.resource_groups.list():
#         if(resource_group.name[0 : len(RESOURCE_GROUP_NAME)] == RESOURCE_GROUP_NAME):
#             previous_resource_group_number = resource_group.name[len(RESOURCE_GROUP_NAME) : len(resource_group.name)]
#             if (previous_resource_group_number != ''):
#                 next_resource_group_number = 0
#                 for i in previous_resource_group_number:
#                     next_resource_group_number = next_resource_group_number * 10 + (int)(i)
#                 next_resource_group_number = next_resource_group_number + 1
#             else:
#                 next_resource_group_number = 1
#     resource_group_name = RESOURCE_GROUP_NAME + str(next_resource_group_number)
#
#     new_resource_group =  resource_management_client.resource_groups.create_or_update(
#         resource_group_name,
#         {"location": LOCATION})
#     return next_resource_group_number, new_resource_group
#
# next_resource_group_number, resource_group = create_resource_group(resource_management_client)
#
#
# VNET_NAME = VNET_NAME + str(next_resource_group_number)
# SUBNET_NAME = SUBNET_NAME + str(next_resource_group_number)
# IP_NAME = IP_NAME + str(next_resource_group_number)
# IP_CONFIG_NAME = IP_CONFIG_NAME + str(next_resource_group_number)
# PUBLIC_KEY_NAME = PUBLIC_KEY_NAME + str(next_resource_group_number)
# PRIVATE_KEY_NAME = PRIVATE_KEY_NAME + str(next_resource_group_number)
# NIC_NAME = NIC_NAME + str(next_resource_group_number)
# VM_NAME = VM_NAME + str(next_resource_group_number)
# NSG_NAME = NSG_NAME + str(next_resource_group_number)
# SECURITY_RULE_SSH = SECURITY_RULE_SSH + str(next_resource_group_number)
# SECURITY_RULE_INBOUND = SECURITY_RULE_INBOUND + str(next_resource_group_number)
# SECURITY_RULE_OUTBOUND = SECURITY_RULE_OUTBOUND + str(next_resource_group_number)
#
#
# # Network and IP address names
#
#
# # Obtain the management object for networks
# network_client = NetworkManagementClient(default_credential, SUBSCRIPTION_ID)
#
# # Provision the virtual network and wait for completion
# poller = network_client.virtual_networks.begin_create_or_update(
#     resource_group.name,
#     VNET_NAME,
#     {
#         "location": LOCATION,
#         "address_space": {"address_prefixes": ["10.0.0.0/16"]},
#     },
# )
#
# vnet_result = poller.result()
#
# print(
#     f"Provisioned virtual network {vnet_result.name} with address \
# prefixes {vnet_result.address_space.address_prefixes}"
# )
#
# # Step 3: Provision the subnet and wait for completion
# poller = network_client.subnets.begin_create_or_update(
#     resource_group.name,
#     VNET_NAME,
#     SUBNET_NAME,
#     {"address_prefix": "10.0.0.0/24"},
# )
# subnet_result = poller.result()
#
# print(
#     f"Provisioned virtual subnet {subnet_result.name} with address \
# prefix {subnet_result.address_prefix}"
# )
#
# # Step 4: Provision an IP address and wait for completion
# poller = network_client.public_ip_addresses.begin_create_or_update(
#     resource_group.name,
#     IP_NAME,
#     {
#         "location": LOCATION,
#         "sku": {"name": "Standard"},
#         "public_ip_allocation_method": "Static",
#         "public_ip_address_version": "IPV4",
#     },
# )
#
# ip_address_result = poller.result()
#
# print(
#     f"Provisioned public IP address {ip_address_result.name} \
# with address {ip_address_result.ip_address}"
# )
#
# nsg = network_client.network_security_groups.begin_create_or_update(
#     resource_group.name,
#     NSG_NAME,
#     {
#         "location": LOCATION,
#         "security_rules": [
#             {
#                 "name": SECURITY_RULE_INBOUND,
#                 "protocol": "TCP",
#                 "source_port_range": "*",
#                 "destination_port_range": "*",
#                 "access": "ALLOW",
#                 "direction": "INBOUND",
#                 "source_address_prefix": "*",
#                 "destination_address_prefix": "*",
#                 "priority": 100,
#             },
#             {
#                 "name": SECURITY_RULE_OUTBOUND,
#                 "protocol": "TCP",
#                 "source_port_range": "*",
#                 "destination_port_range": "*",
#                 "access": "ALLOW",
#                 "direction": "OUTBOUND",
#                 "source_address_prefix": "*",
#                 "destination_address_prefix": "*",
#                 "priority": 100,
#             }
#         ]
#     }
# )
#
# print(
#     f"Provisioned Network Security Group with name {nsg.result().name}"
# )
#
# # Step 5: Provision the network interface client
# poller = network_client.network_interfaces.begin_create_or_update(
#     resource_group.name,
#     NIC_NAME,
#     {
#         "location": LOCATION,
#         "ip_configurations": [
#             {
#                 "name": IP_CONFIG_NAME,
#                 "subnet": {"id": subnet_result.id},
#                 "public_ip_address": {"id": ip_address_result.id},
#             }
#         ],
#         "network_security_group": {
#             "id": nsg.result().id
#         }
#     },
# )
#
# nic_result = poller.result()
#
# print(f"Provisioned network interface client {nic_result.name}")
#
# # Step 6: Provision the virtual machine
#
# # Obtain the management object for virtual machines
# compute_client = ComputeManagementClient(default_credential, SUBSCRIPTION_ID)
#
#
# print(
#     f"Provisioning virtual machine {VM_NAME}; this operation might \
# take a few minutes."
# )
#
# # Provision the VM specifying only minimal arguments, which defaults
# # to an Ubuntu 18.04 VM on a Standard DS1 v2 plan with a public IP address
# # and a default virtual network/subnet.
#
# public_key_create_result = compute_client.ssh_public_keys.create(
#     resource_group.name,
#     PUBLIC_KEY_NAME,
#     {
#        "location": LOCATION,
#     }
# )
#
# print(public_key_create_result)
#
#
# ssh_result = compute_client.ssh_public_keys.generate_key_pair(
#     resource_group.name,
#     PUBLIC_KEY_NAME,
# )
#
#
# # f = open(PRIVATE_KEY_NAME + ".pem", "w", newline='')
# # f.write(ssh_result.private_key)
# # os.chmod(PRIVATE_KEY_NAME + ".pem", 33024)
#
# descriptor = os.open(
#     path=PRIVATE_KEY_NAME + ".pem",
#     flags=(
#         os.O_WRONLY  # access mode: write only
#         | os.O_CREAT  # create if not exists
#     ),
#     mode=0o600
# )
#
# with open(descriptor, 'w', newline='') as fh:
#     fh.write(ssh_result.private_key)
#     # the descriptor is automatically closed when fh is closed
#     fh.close()
#
# ssh_key = compute_client.ssh_public_keys.get(
#     resource_group_name=resource_group.name,
#     ssh_public_key_name=PUBLIC_KEY_NAME
# ).public_key
#
#
# poller = compute_client.virtual_machines.begin_create_or_update(
#     resource_group.name,
#     VM_NAME,
#     {
#         "location": LOCATION,
#         "storage_profile": {
#             "image_reference": {
#                 "publisher": "Canonical",
#                 "offer": "0001-com-ubuntu-server-focal",
#                 "sku": "20_04-lts-gen2",
#                 "version": "latest",
#             }
#         },
#         "hardware_profile": {"vm_size": "Standard_DC1s_v2"},
#         "os_profile": {
#             "computer_name": VM_NAME,
#             "admin_username": USERNAME,
#             "admin_password": PASSWORD,
#             "linux_configuration": {
#                 "disable_password_authentication": True,
#                 "ssh": {
#                     "public_keys": [
#                         {
#                             "path": "/home/" + USERNAME + "/.ssh/authorized_keys",
#                             "key_data": ssh_key,
#                         }
#                     ]
#                 }
#             }
#         },
#         "network_profile": {
#             "network_interfaces": [
#                 {
#                     "id": nic_result.id,
#                 }
#             ]
#         },
#     },
# )
#
# vm_result = poller.result()
#
# print(f"Provisioned virtual machine {vm_result.name} with the following specs {vm_result}")
#
# #  pull my enclave before running the client app
# #  then run user's app in my enclave
# #  criptez aplicatia care trebuie deployata, am si cheia de criptare
# #  decriptarea se intampla doar in enclava
# #  decriptez aplicatia
# #  se da drumu la aplicatie
# run_command_parameters = {
#     'command_id': 'RunShellScript', # For linux, don't change it
#     'script': [
#         'echo set debconf to Noninteractive',
#         'echo "debconf debconf/frontend select Noninteractive" | sudo debconf-set-selections',
#         'yes yes | sudo apt-get install build-essential git gcc -y -q',
#         'yes yes | sudo apt-get install build-essential',
#         'yes | sudo apt -y install g++',
#         'cd /opt',
#         'mkdir intel',
#         'cd intel',
#         'echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list',
#         'sudo wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add',
#         'sudo apt-get update',
#         'yes | sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql libsgx-uae-service',
#         'yes | sudo apt-get install libsgx-urts-dbgsym libsgx-enclave-common-dbgsym libsgx-dcap-ql-dbgsym libsgx-dcap-default-qpl-dbgsym',
#         'yes | sudo apt-get install libsgx-dcap-default-qpl libsgx-launch libsgx-urts',
#         'sudo wget - https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.19.100.3.bin',
#         'sudo chmod +x sgx_linux_x64_sdk_2.19.100.3.bin',
#         'yes yes | sudo ./sgx_linux_x64_sdk_2.19.100.3.bin',
#         '. /opt/intel/sgxsdk/environment',
#         'yes | sudo apt-get install libsgx-enclave-common-dev libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev',
#         'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/SampleCode/RemoteAttestation/sample_libcrypto',
#         'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/SampleCode/RemoteAttestation/sample_libcrypto',
#         # SETUP NODEJS for PCCS install
#         'sudo curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -',
#         'yes | sudo apt-get install -y nodejs',
#         'yes | sudo apt-get install python3 cracklib-runtime',
#         #instal DCAP PCCS & CONFIGURE
#         'yes | sudo apt-get install expect autotools-dev automake libssl-dev',
#         'cd /home/azureuser/',
#         'wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz',
#         'tar xf openssl-1.1.0i.tar.gz',
#         'cd openssl-1.1.0i',
#         './config --prefix=/opt/openssl/1.1.0i --openssldir=/opt/openssl/1.1.0i',
#         'sudo make',
#         'sudo make install',
#         'sudo git clone https://github.com/taiwolfB/IntelSGX_LINUX_SAMPLES.git',
#         'cd IntelSGX_LINUX_SAMPLES',
#         'sudo chmod 777 install_dcap_pccs.exp',
#         'sudo expect install_dcap_pccs.exp',
#         'cd ../',
#         'sudo git clone https://github.com/taiwolfB/INTEL_SGX_RA_SAMPLE_UPDATED_.git'
#     ]
# }
# poller = compute_client.virtual_machines.begin_run_command(
#     resource_group.name,
#     vm_result.name,
#     run_command_parameters)
#
# result = poller.result()  # Blocking till executed
# print(result.value[0].message)  # stdout/stderr
#
#
#
#
# # # # Create ACR
#
# # # ACR_NAME="dsacrbogdantailup30442"
# # # audience = "https://management.azure.com"
#
# # # container_service_client = ContainerRegistryManagementClient(
# # #     subscription_id=SUBSCRIPTION_ID,
# # #     credential=credential,
# # #     audience=audience)
# # # registry = Registry(
# # #     location=LOCATION,
# # #     sku=Sku(name="Standard"),
# # #     admin_user_enabled=True)
# # # registry_creation = container_service_client.registries.begin_create(
# # #     resource_group_name=RESOURCE_GROUP_NAME,
# # #     registry_name=ACR_NAME,
# # #     registry=registry)
# # # registry = registry_creation.result()
#
#
# # # connection = Connection(base_url="https://dev.azure.com/TailupBogdan30442/")
#
#
