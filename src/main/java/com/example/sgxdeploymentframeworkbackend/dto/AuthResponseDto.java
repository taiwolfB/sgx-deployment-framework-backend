package com.example.sgxdeploymentframeworkbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
public class AuthResponseDto {

    private String message;
    private String loggedInUser;
    private String userPrincipalName;
    private Integer httpCode;
}
