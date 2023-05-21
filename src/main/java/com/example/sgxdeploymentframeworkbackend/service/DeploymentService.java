package com.example.sgxdeploymentframeworkbackend.service;

import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.DeviceCodeCredential;
import com.azure.identity.DeviceCodeCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.compute.fluent.models.SshPublicKeyGenerateKeyPairResultInner;
import com.azure.resourcemanager.compute.fluent.models.SshPublicKeyResourceInner;
import com.azure.resourcemanager.compute.models.*;
import com.azure.resourcemanager.network.models.*;
import com.azure.resourcemanager.network.models.IpVersion;
import com.azure.resourcemanager.resources.models.ResourceGroup;
import com.example.sgxdeploymentframeworkbackend.config.WebSocketListener;
import com.example.sgxdeploymentframeworkbackend.constants.DeploymentProperties;
import com.example.sgxdeploymentframeworkbackend.dto.*;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.*;

@Service
@Slf4j
public class DeploymentService {

    @Autowired
    private WebSocketListener webSocketListener;

    @Autowired
    private DeploymentProperties deploymentProperties;


    private AzureResourceManager azureResourceManager;

    public AuthResponseDto authorize(AuthDto authDto) {
        AuthResponseDto authResponseDto = new AuthResponseDto();
        DeviceCodeCredential deviceCodeCredential = new DeviceCodeCredentialBuilder()
                .tenantId(authDto.getTenantId())
                .challengeConsumer(challenge -> {
                    System.out.println(challenge.getMessage());
                    WebSocketDto webSocketDto = new WebSocketDto();
                    webSocketDto.setUrl("https://microsoft.com/devicelogin");
                    webSocketDto.setDeviceCode(challenge.getMessage().substring(100, 109));
                    webSocketListener.pushSystemStatusToDeviceCodeWebSocket(webSocketDto);
                })
                .build();

        AzureProfile azureProfile = new AzureProfile(AzureEnvironment.AZURE);
        azureResourceManager  = AzureResourceManager
                .authenticate(deviceCodeCredential, azureProfile)
                .withSubscription(authDto.getSubscriptionId());

        azureResourceManager.accessManagement().activeDirectoryUsers().list().forEach(user -> {
            authResponseDto.setLoggedInUser(user.name());
            authResponseDto.setUserPrincipalName(user.userPrincipalName());
            deploymentProperties.setLoggedInUser(user.name());
            deploymentProperties.setUserPrincipalName(user.userPrincipalName());
        });


        authResponseDto.setMessage("Authentication successful.");
        authResponseDto.setHttpCode(200);
        deploymentProperties.setSubscriptionId(authDto.getSubscriptionId());
        deploymentProperties.setTenantId(authDto.getTenantId());
        return authResponseDto;
    }

    private List<String> createScript() {
        List<String> script = new ArrayList<>();
        script.add("echo set debconf to Noninteractive");
        script.add("echo \"debconf debconf/frontend select Noninteractive\" | sudo debconf-set-selections");
        script.add("yes yes | sudo apt-get install build-essential git gcc -y -q");
        script.add("yes yes | sudo apt-get install build-essential");
        script.add("yes | sudo apt -y install g++");
        script.add("cd /opt");
        script.add("mkdir intel");
        script.add("cd intel");
        script.add("echo \"deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main\" | sudo tee /etc/apt/sources.list.d/intel-sgx.list");
        script.add("sudo wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add");
        script.add("sudo apt-get update");
        script.add("yes | sudo apt-get install libsgx-epid libsgx-quote-ex libsgx-dcap-ql libsgx-uae-service");
        script.add("yes | sudo apt-get install libsgx-urts-dbgsym libsgx-enclave-common-dbgsym libsgx-dcap-ql-dbgsym libsgx-dcap-default-qpl-dbgsym");
        script.add("yes | sudo apt-get install libsgx-dcap-default-qpl libsgx-launch libsgx-urts");
        script.add("sudo wget - https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.19.100.3.bin");
        script.add("sudo chmod +x sgx_linux_x64_sdk_2.19.100.3.bin");
        script.add("yes yes | sudo ./sgx_linux_x64_sdk_2.19.100.3.bin");
        script.add(". /opt/intel/sgxsdk/environment");
        script.add("yes | sudo apt-get install libsgx-enclave-common-dev libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev");
        script.add("export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/SampleCode/RemoteAttestation/sample_libcrypto");
        script.add("set LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/intel/sgxsdk/SampleCode/RemoteAttestation/sample_libcrypto");
//        # SETUP NODEJS for PCCS install
        script.add("sudo curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -");
        script.add("yes | sudo apt-get install -y nodejs");
        script.add("yes | sudo apt-get install python3 cracklib-runtime");
//        #instal DCAP PCCS & CONFIGURE
        script.add("yes | sudo apt-get install expect autotools-dev automake libssl-dev");
        script.add("cd /home/azureuser/");
        script.add("wget https://www.openssl.org/source/openssl-1.1.1i.tar.gz");
        script.add("tar xf openssl-1.1.1i.tar.gz");
        script.add("cd openssl-1.1.1i");
        script.add("./config --prefix=/opt/openssl/1.1.1i --openssldir=/opt/openssl/1.1.1i");
        script.add("sudo make");
        script.add("sudo make install");
        script.add("cd ../");
        script.add("sudo git clone https://github.com/taiwolfB/sgx-deployment-framework-remote-attestation");
        script.add("cd sgx-deployment-framework-remote-attestation");
        script.add("sudo chmod 777 install_dcap_pccs.exp");
        script.add("sudo expect install_dcap_pccs.exp");
        script.add("sudo ./bootstrap");
        script.add("sudo ./configure --with-openssldir=/opt/openssl/1.1.1i");
        script.add("sudo make");
        return script;
    }

    private void updateDeploymentProperties() {
        Integer previousResourceGroupNumber = 0;
        for (ResourceGroup resourceGroup: azureResourceManager.resourceGroups().list()) {
            if (resourceGroup.name().startsWith(deploymentProperties.getResourceGroupName())) {
                StringTokenizer st = new StringTokenizer(resourceGroup.name(),deploymentProperties.getResourceGroupName());
                if (st.hasMoreTokens()) {
                    previousResourceGroupNumber = Integer.parseInt(st.nextElement().toString());
                }
            }
        }
        deploymentProperties.setNextResourceNumber(previousResourceGroupNumber + 1);
    }

    @SneakyThrows
    public DeploymentDto deploy(DeploymentDto deploymentDto) throws IOException {
        DeploymentDto responseDeploymentDto = new DeploymentDto();
        try {
            updateDeploymentProperties();
            deploymentProperties.setVmName(deploymentDto.getApplicationName());
            WebSocketDeploymentLogDto webSocketDeploymentLogDto = new WebSocketDeploymentLogDto();
            ResourceGroup resourceGroup = azureResourceManager.resourceGroups()
                    .define(deploymentProperties.getResourceGroupName() + deploymentProperties.getNextResourceNumber())
                    .withRegion(deploymentProperties.getLocation())
                    .create();
            log.info("Provisioned Resource Group " + resourceGroup.name());
            webSocketDeploymentLogDto.setMessage("Provisioned Resource Group " + resourceGroup.name());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);


            Network network = azureResourceManager.networks()
                    .define(deploymentProperties.getVnetName() + deploymentProperties.getNextResourceNumber())
                    .withRegion(deploymentProperties.getLocation())
                    .withExistingResourceGroup(resourceGroup)
                    .withAddressSpace(deploymentProperties.getVnetAddressSpace())
                    .withSubnet(deploymentProperties.getSubnetName() + deploymentProperties.getNextResourceNumber(),
                            deploymentProperties.getSubnetAddressSpace())
                    .create();
            log.info("Provisioned virtual network "
                    + network.name()
                    + " with address prefix "
                    + network.addressSpaces()
                    + " and Subnet Address space "
                    + deploymentProperties.getSubnetAddressSpace());
            webSocketDeploymentLogDto.setMessage("Provisioned virtual network "
                    + network.name()
                    + " with address prefix "
                    + network.addressSpaces()
                    + " and Subnet Address space "
                    + deploymentProperties.getSubnetAddressSpace()
            );
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            PublicIpAddress ipAddress = azureResourceManager.publicIpAddresses()
                    .define(deploymentProperties.getIpName() + deploymentProperties.getNextResourceNumber())
                    .withRegion(deploymentProperties.getLocation())
                    .withExistingResourceGroup(resourceGroup)
                    .withStaticIP()
                    .withSku(PublicIPSkuType.STANDARD)
                    .withIpAddressVersion(IpVersion.IPV4)
                    .create();
            log.info("Provisioned ip address "
                    + ipAddress.name()
                    + " with address "
                    + ipAddress.ipAddress());
            webSocketDeploymentLogDto.setMessage("Provisioned ip address "
                    + ipAddress.name()
                    + " with address "
                    + ipAddress.ipAddress());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            NetworkSecurityGroup networkSecurityGroup = azureResourceManager.networkSecurityGroups()
                    .define(deploymentProperties.getNsgName() + deploymentProperties.getNextResourceNumber())
                    .withRegion(deploymentProperties.getLocation())
                    .withExistingResourceGroup(resourceGroup)
                    .defineRule(deploymentProperties.getSecurityRuleInboundName())
                    .allowInbound()
                    .fromAnyAddress()
                    .fromAnyPort()
                    .toAnyAddress()
                    .toAnyPort()
                    .withProtocol(SecurityRuleProtocol.TCP)
                    .withPriority(deploymentProperties.getSecurityRulePriority())
                    .withDescription(deploymentProperties.getSecurityRuleInboundDescription())
                    .attach()
                    .defineRule(deploymentProperties.getSecurityRuleOutboundName())
                    .allowOutbound()
                    .fromAnyAddress()
                    .fromAnyPort()
                    .toAnyAddress()
                    .toAnyPort()
                    .withProtocol(SecurityRuleProtocol.TCP)
                    .withPriority(deploymentProperties.getSecurityRulePriority())
                    .withDescription(deploymentProperties.getSecurityRuleOutboundDescription())
                    .attach()
                    .create();
            log.info("Provisioned Network Security group " + networkSecurityGroup.name());
            webSocketDeploymentLogDto.setMessage("Provisioned Network Security group " + networkSecurityGroup.name());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            NetworkInterface networkInterface= azureResourceManager.networkInterfaces()
                    .define(deploymentProperties.getNicName() + deploymentProperties.getNextResourceNumber())
                    .withRegion(deploymentProperties.getLocation())
                    .withExistingResourceGroup(resourceGroup)
                    .withExistingPrimaryNetwork(network)
                    .withSubnet(deploymentProperties.getSubnetName() + deploymentProperties.getNextResourceNumber())
                    .withPrimaryPrivateIPAddressDynamic()
                    .withExistingPrimaryPublicIPAddress(ipAddress)
                    .withExistingNetworkSecurityGroup(networkSecurityGroup)
                    .create();
            log.info("Provisioned network interface " + networkInterface.name());
            webSocketDeploymentLogDto.setMessage("Provisioned network interface " + networkInterface.name());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            azureResourceManager
                    .virtualMachines()
                    .manager()
                    .serviceClient()
                    .getSshPublicKeys()
                    .create(resourceGroup.name(),
                            deploymentProperties.getPublicKeyName() + deploymentProperties.getNextResourceNumber(),
                            new SshPublicKeyResourceInner()
                                    .withLocation(deploymentProperties.getLocation()));
            SshPublicKeyGenerateKeyPairResultInner sshPublicKeyGenerateKeyPairResultInner = azureResourceManager
                    .virtualMachines()
                    .manager()
                    .serviceClient()
                    .getSshPublicKeys()
                    .generateKeyPair(resourceGroup.name(),
                            deploymentProperties.getPublicKeyName() + deploymentProperties.getNextResourceNumber());
            log.info("Provisioned ssh keys");
            webSocketDeploymentLogDto.setMessage("Provisioned ssh keys");
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            FileWriter fileWriter = new FileWriter(resourceGroup.name()
                    + "_"
                    + deploymentProperties.getVmName()
                    + "_"
                    + ipAddress.ipAddress()
                    + ".pem");
            fileWriter.write(sshPublicKeyGenerateKeyPairResultInner.privateKey());
            fileWriter.close();

            log.info("SSH key = " + sshPublicKeyGenerateKeyPairResultInner.privateKey());
            webSocketDeploymentLogDto.setMessage("SSH KEY");
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);
            webSocketDeploymentLogDto.setMessage(sshPublicKeyGenerateKeyPairResultInner.privateKey());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            log.info("Provisioning virtual machine, this might take a few minutes.");
            webSocketDeploymentLogDto.setMessage("Provisioning virtual machine, this might take a few minutes.");
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            SshPublicKey sshPublicKey = new SshPublicKey()
                    .withPath("/home/" + deploymentProperties.getUsername() + "/.ssh/authorized_keys")
                    .withKeyData(sshPublicKeyGenerateKeyPairResultInner.publicKey());
            SshConfiguration sshConfiguration = new SshConfiguration()
                    .withPublicKeys(Collections.singletonList(sshPublicKey));
            LinuxConfiguration linuxConfiguration = new LinuxConfiguration()
                    .withDisablePasswordAuthentication(true)
                    .withSsh(sshConfiguration);


            VirtualMachine virtualMachine = azureResourceManager.virtualMachines()
                    .define(deploymentProperties.getVmName())
                    .withRegion(deploymentProperties.getLocation())
                    .withExistingResourceGroup(resourceGroup)
                    .withExistingPrimaryNetworkInterface(networkInterface)
                    .withPopularLinuxImage(KnownLinuxVirtualMachineImage.UBUNTU_SERVER_20_04_LTS_GEN2)
                    .withRootUsername(deploymentProperties.getUsername())
                    .withRootPassword(deploymentProperties.getPassword())
                    .withSsh(sshPublicKey.keyData())
                    .withComputerName(deploymentProperties.getComputerName() + deploymentProperties.getNextResourceNumber())
                    .withSize(deploymentProperties.getVmSize())
                    .create();

            log.info("Provisioned virtual machine " + virtualMachine.name());
            webSocketDeploymentLogDto.setMessage("Provisioned virtual machine " + virtualMachine.name());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            log.info("Running startup script.");
            webSocketDeploymentLogDto.setMessage("Running startup script.");
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);
            RunCommandInput runCommandInput = new RunCommandInput()
                    .withCommandId("RunShellScript")
                    .withScript(createScript());
            RunCommandResult runCommandResult = azureResourceManager
                    .virtualMachines()
                    .runCommand(resourceGroup.name(), virtualMachine.name(), runCommandInput);

            log.info("Initialize script result: ");
            runCommandResult.value().forEach(l -> log.info(l.message()));

            ProcessBuilder processBuilder = new
                    ProcessBuilder("curl", "ipinfo.io/ip");
            Process workerProcess = processBuilder.start();
            workerProcess.waitFor();

            BufferedReader bufferedReader = new BufferedReader(
                    new InputStreamReader(
                            workerProcess.getInputStream()
                    ));
            String backendIpAddress = "";
            while ((backendIpAddress = bufferedReader.readLine()) != null) {
                break;
            }
            webSocketDeploymentLogDto.setMessage("Starting SGX Validation between backend server located at "
                    + backendIpAddress + " and target VM located at " + ipAddress.ipAddress());
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            RunCommandInput startSGXClientCommand = new RunCommandInput()
                    .withCommandId("RunShellScript")
                    .withScript(createSgxClientScript(deploymentProperties.getVmName(), backendIpAddress));
            RunCommandResult startSGXClientCommandResult = azureResourceManager
                    .virtualMachines()
                    .runCommand(resourceGroup.name(), virtualMachine.name(), startSGXClientCommand);
            webSocketDeploymentLogDto.setMessage("");
            startSGXClientCommandResult.value().forEach(result -> {
                webSocketDeploymentLogDto.setMessage(result.message());
                webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);
                log.info(result.message());
            });
            webSocketListener.pushSystemStatusToDeploymentLogsWebSocket(webSocketDeploymentLogDto);

            responseDeploymentDto.setMessage("Deployment success!");
            responseDeploymentDto.setHttpCode(200);
        } catch(Exception ex) {
            log.error(ex.getMessage());
            ex.printStackTrace();
            responseDeploymentDto.setMessage(ex.getMessage());
            responseDeploymentDto.setHttpCode(400);
        }
        return responseDeploymentDto;
    }

    public AuthResponseDto checkAuthorization(AuthDto authDto) {
        AuthResponseDto authResponseDto =  new AuthResponseDto();
        try {
            if (authDto.getLoggedInUser().equals(deploymentProperties.getLoggedInUser()) &&
                    authDto.getUserPrincipalName().equals(deploymentProperties.getUserPrincipalName()) &&
                    azureResourceManager != null) {
                authResponseDto.setHttpCode(200);
                authResponseDto.setMessage("The user is authorized to perform the requested actions.");
                log.info("The user "
                        + authDto.getLoggedInUser()
                        + "is authorized to perform the requested actions.");
            } else {
                authResponseDto.setHttpCode(401);
                authResponseDto.setMessage("The user is NOT authorized to perform the requested actions.");
                log.error("The user "
                        + authDto.getLoggedInUser()
                        + " is NOT authorized to perform the requested actions.");
            }
        } catch(Exception ex) {
            authResponseDto.setMessage("The user is NOT authorized to perform the requested actions.");
            authResponseDto.setHttpCode(401);
            log.error(ex.getMessage());
        }
        return authResponseDto;
    }

    public List<DeployedApplicationDto> findDeployedApplications() {
        List<DeployedApplicationDto> deployedApplications = new ArrayList<>();
        try {
            azureResourceManager.virtualMachines().list().forEach(virtualMachine -> {
                if (virtualMachine.resourceGroupName().contains(deploymentProperties.getResourceGroupName().toUpperCase())) {
                    DeployedApplicationDto deployedApplicationDto = new DeployedApplicationDto();
                    deployedApplicationDto.setApplicationName(virtualMachine.name());
                    deployedApplicationDto.setVirtualMachineIp(virtualMachine.getPrimaryPublicIPAddress().ipAddress());
                    deployedApplicationDto.setSshUsername(deploymentProperties.getUsername());
                    String sshKey = "";
                    File pemFile = new File(virtualMachine.resourceGroupName()
                            + "_"
                            + virtualMachine.name()
                            + "_"
                            + virtualMachine.getPrimaryPublicIPAddress().ipAddress()
                            + ".pem");
                    Scanner fileReader = null;
                    try {
                        fileReader = new Scanner(pemFile);
                    } catch (FileNotFoundException e) {
                        sshKey = "PEM FILE MIGHT HAVE BEEN DELETED FROM THE SYSTEM. PLEASE CONTACT AN ADMINISTRATOR.";
                        log.error("PEM FILE MIGHT HAVE BEEN DELETED FROM THE SYSTEM. PLEASE CONTACT AN ADMINISTRATOR");
                    }
                    while (fileReader.hasNextLine()) {
                        sshKey =  sshKey.concat(fileReader.nextLine() + "\n");
                    }
                    fileReader.close();
                    deployedApplicationDto.setSshKey(sshKey);
                    deployedApplications.add(deployedApplicationDto);
                }
            });
            return deployedApplications;
        } catch (Exception ex) {
            log.error(ex.getMessage());
            ex.printStackTrace();
            return deployedApplications;
        }
    }
    private List<String> createSgxClientScript(String deploymentFileLocation, String backendIpLocation) {
        List<String> script = new ArrayList<>();
        script.add("cd /home/azureuser/sgx-deployment-frameowrk-remote-attestation");
        script.add("sudo chmod 777 ./run-client");
        script.add("sudo chmod 777 ./run-server");
        script.add("sudo chmod 777 ./client");
        script.add("sudo chmod 777 ./sp");
        script.add("sudo chmod 777 ./mrsigner");
        script.add("sudo chmod 777 ./" + deploymentFileLocation);
        script.add("sudo ./run-client -a " + deploymentFileLocation  + " " + backendIpLocation + ":8085");
        script.add("./" + deploymentFileLocation);
        return script;
    }
}
