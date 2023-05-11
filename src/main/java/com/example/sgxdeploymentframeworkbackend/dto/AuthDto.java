package com.example.sgxdeploymentframeworkbackend.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthDto {

    private String subscriptionId;
    private String tenantId;
    private String loggedInUser;
    private String userPrincipalName;
}
