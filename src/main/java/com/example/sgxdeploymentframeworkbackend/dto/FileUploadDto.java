package com.example.sgxdeploymentframeworkbackend.dto;


import lombok.Data;

@Data
public class FileUploadDto {
//    private byte[] byteArray;
    private String encodedByteArray;
    private String applicationName;
}
