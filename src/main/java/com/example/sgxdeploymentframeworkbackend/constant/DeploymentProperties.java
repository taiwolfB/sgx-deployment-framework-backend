package com.example.sgxdeploymentframeworkbackend.constants;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "deployment")
@Data
public class DeploymentProperties {

    private String userPrincipalName;
    private String loggedInUser;
    private String subscriptionId;
    private String tenantId;
    private String resourceGroupName;
    private String location;
    private String vnetName;
    private String vnetAddressSpace;
    private String subnetName;
    private String subnetAddressSpace;
    private String ipName;
    private String ipConfigName;
    private String publicKeyName;
    private String privateKeyName;
    private String nsgName;
    private String nicName;
    private String vmName;
    private String computerName;
    private String imagePublisher;
    private String imageOffer;
    private String imageSku;
    private String imageVersion;
    private String vmSize;
    private String username;
    private String password;
    private String securityRuleInboundName;
    private String securityRuleOutboundName;
    private Integer securityRulePriority;
    private String securityRuleInboundDescription;
    private String securityRuleOutboundDescription;
    private String securityRuleSshName;

    private Integer loginCodeIncrement;

    private Integer nextResourceNumber;

}
