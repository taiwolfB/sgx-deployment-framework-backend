package com.example.sgxdeploymentframeworkbackend.dto;

import lombok.Data;

@Data
public class WebSocketDeploymentLogDto {

    private String message;
    private String deploymentName;
}
