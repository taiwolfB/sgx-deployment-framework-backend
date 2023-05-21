package com.example.sgxdeploymentframeworkbackend.config;

import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.messaging.simp.config.ChannelRegistration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfiguration implements WebSocketMessageBrokerConfigurer {

    @Autowired
    private Environment environment;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        registry.enableSimpleBroker("/azure");
    }

    @SneakyThrows
    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        final ProcessBuilder processBuilder = new
                ProcessBuilder("curl", "ipinfo.io/ip");
        final Process workerProcess = processBuilder.start();
        workerProcess.waitFor();

        final BufferedReader bufferedReader = new BufferedReader(
                new InputStreamReader(
                        workerProcess.getInputStream()
                ));
        String ipAddress = "";
        while ((ipAddress = bufferedReader.readLine()) != null) {
            break;
        }
        final String frontend_address = "http://" + ipAddress + ":8083";
        bufferedReader.close();
        registry.addEndpoint("device-code-provider")
                .setAllowedOrigins(environment.getProperty("frontend.server"), frontend_address, "http://localhost:8083")
                .withSockJS();
        registry.addEndpoint("deployment-logs")
                .setAllowedOrigins(environment.getProperty("frontend.server"), frontend_address, "http://localhost:8083")
                .withSockJS();
    }

    @Override
    public void configureClientOutboundChannel(ChannelRegistration registration) {
        registration.taskExecutor()
                .corePoolSize(10)
                .maxPoolSize(20);
    }

    @Override
    public void configureWebSocketTransport(WebSocketTransportRegistration registration) {
        registration.setSendTimeLimit( 15 * 1000)
                .setSendBufferSizeLimit( 512 * 1024)
                .setMessageSizeLimit( 128 * 1024);
    }
}
