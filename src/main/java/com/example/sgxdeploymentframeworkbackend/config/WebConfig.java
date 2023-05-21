package com.example.sgxdeploymentframeworkbackend.config;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;

@Configuration
@EnableWebMvc
@Slf4j
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private Environment environment;

    @SneakyThrows
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        ProcessBuilder processBuilder = new
                ProcessBuilder("curl", "ipinfo.io/ip");
        Process workerProcess = processBuilder.start();
        workerProcess.waitFor();

        BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(
                        workerProcess.getInputStream()
                ));
        String ipAddress = "";
        while ((ipAddress = bufferedReader.readLine()) != null) {
            break;
        }

        String frontend_address = "http://" + ipAddress + ":8083";
        bufferedReader.close();
        registry.addMapping("/**")
                .allowedOrigins(environment.getProperty("frontend.server"), frontend_address, "http://localhost:8083")
                .allowedMethods("GET", "PUT", "POST", "DELETE")
                .allowedHeaders("Accept", "Content-Type")
                .exposedHeaders("Accept", "Content-Type")
                .allowCredentials(false).maxAge(3600);
    }
}
