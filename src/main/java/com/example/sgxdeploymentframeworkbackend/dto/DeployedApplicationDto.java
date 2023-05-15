package com.example.sgxdeploymentframeworkbackend.dto;

import lombok.Data;

@Data
public class DeployedApplicationDto {

    private String applicationName;
    private String virtualMachineIp;
    private String sshKey;
    private String sshUsername;
}
