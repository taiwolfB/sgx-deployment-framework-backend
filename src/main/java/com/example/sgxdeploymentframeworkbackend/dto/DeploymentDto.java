package com.example.sgxdeploymentframeworkbackend.dto;

import lombok.Data;

@Data
public class DeploymentDto {

    private String applicationName;
    private String message;
    private Integer httpCode;
}
