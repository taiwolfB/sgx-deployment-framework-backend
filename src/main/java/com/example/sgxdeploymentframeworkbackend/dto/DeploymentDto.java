package com.example.sgxdeploymentframeworkbackend.dto;

import lombok.Data;

@Data
public class DeploymentDto {

    // TODO think of fields here
    private String applicationName;
    private String message;
    private Integer httpCode;
}
