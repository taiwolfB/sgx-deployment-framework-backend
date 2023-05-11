package com.example.sgxdeploymentframeworkbackend.controller;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.*;
//import com.azure.resourcemanager.subscription.SubscriptionManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.List;

@RestController
public class TestController {

    @Autowired
    private Environment environment;

    private String resolvePythonScriptPath(String path){
        File file = new File(path);
        System.out.println(file.getAbsolutePath());
        return file.getAbsolutePath();
    }

    @GetMapping("/test")
    public String gett() throws IOException, InterruptedException {
//        ProcessBuilder processBuilder = new ProcessBuilder("python3", resolvePythonScriptPath("deploy_script.py"));
//        processBuilder.redirectErrorStream(true);
//
//        Process process = processBuilder.start();
//        System.out.println(process.getErrorStream().toString());
//        System.out.println(process.getInputStream().toString());
//
//        int exitCode = process.waitFor();
//
//        System.out.println(process.getOutputStream().toString());

//        String Script_Path = resolvePythonScriptPath("deploy_script.py");
//        ProcessBuilder Process_Builder = new
//                ProcessBuilder("python",Script_Path)
//                .inheritIO();
//
//        Process Demo_Process = Process_Builder.start();
//        Demo_Process.waitFor();
//
//        BufferedReader Buffered_Reader = new BufferedReader(
//                new InputStreamReader(
//                        Demo_Process.getInputStream()
//                ));
//        String Output_line = "";
//
//        while ((Output_line = Buffered_Reader.readLine()) != null) {
//            System.out.println(Output_line);
//        }
//        return "YES";
        return "TEST";
    }
}
