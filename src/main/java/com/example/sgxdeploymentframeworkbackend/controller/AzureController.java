package com.example.sgxdeploymentframeworkbackend.controller;

import com.example.sgxdeploymentframeworkbackend.dto.*;
import com.example.sgxdeploymentframeworkbackend.service.DeploymentService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/azure")
@Slf4j
public class AzureController {

    @Autowired
    private DeploymentService deploymentService;


    @PostMapping("/authorize")
    public AuthResponseDto authorizeAzureAccount(@RequestBody AuthDto authDto){
        AuthResponseDto authResponseDto = new AuthResponseDto();
        try {
           authResponseDto = deploymentService.authorize(authDto);
           return authResponseDto;
        } catch (Exception ex) {
            log.error(ex.getMessage());
            ex.printStackTrace();
            authResponseDto.setMessage("Failed to authenticate user due to wrong subscription id or wrong tenant id.");
            authResponseDto.setHttpCode(400);
            return authResponseDto;
        }
    }

    @PostMapping("/deploy")
    public DeploymentDto deploy(@RequestBody DeploymentDto deploymentDto) throws IOException {
        DeploymentDto responseDeploymentDto = new DeploymentDto();
        try {
           responseDeploymentDto =  deploymentService.deploy(deploymentDto);
        } catch(Exception ex) {
            log.error(ex.getMessage());
            ex.printStackTrace();
        }
        return responseDeploymentDto;
    }

    @PostMapping("/is-authorized")
    public AuthResponseDto isAuthorized(@RequestBody AuthDto authDto) {
        AuthResponseDto authResponseDto = new AuthResponseDto();
        try {
            return deploymentService.checkAuthorization(authDto);
        } catch (Exception ex) {
            authResponseDto.setHttpCode(400);
            authResponseDto.setMessage(ex.getMessage());
            log.error(ex.getMessage());
            return authResponseDto;
        }
    }

    @PostMapping(value = "/upload")
    public FileUploadResponseDto upload(@RequestBody FileUploadDto fileUploadDto) throws IOException {
        FileUploadResponseDto fileUploadResponseDto = new FileUploadResponseDto();
        try {
            System.out.println(fileUploadDto.getEncodedByteArray());
            byte[] fileBytes = Base64.getDecoder().decode(fileUploadDto.getEncodedByteArray().getBytes());
            OutputStream os = new FileOutputStream(fileUploadDto.getApplicationName());
            os.write(fileBytes);
            os.close();
            fileUploadResponseDto.setMessage("Application executable successfully uploaded.");
            fileUploadResponseDto.setHttpCode(200);
        } catch (Exception ex) {
            log.error(ex.getMessage());
            ex.printStackTrace();
            fileUploadResponseDto.setMessage(ex.getMessage());
            fileUploadResponseDto.setHttpCode(400);
        }
        return fileUploadResponseDto;
    }

    @GetMapping("/deployed-applications")
    public List<DeployedApplicationDto> getDeployedApplications() {
        return deploymentService.findDeployedApplications();
    }

    @GetMapping("/unauthorize")
    public String unauthorizeAccount() throws IOException, InterruptedException {
        return "YES";
    }
}
