package com.example.sgxdeploymentframeworkbackend.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.messaging.SessionSubscribeEvent;

@Component
@Slf4j
public class CustomApplicationListener implements ApplicationListener<ApplicationEvent> {
    @Override
    public void onApplicationEvent(ApplicationEvent event)
    {
        if (event instanceof SessionSubscribeEvent)
        {
            log.debug("subscribe event received. Some params - ");
            final SessionSubscribeEvent se = (SessionSubscribeEvent) (event);
            final StompHeaderAccessor headers = StompHeaderAccessor.wrap(se.getMessage());
            log.debug("sessionId: {}", headers.getSessionId());
            log.debug("sessionAttributes: {}", headers.getSessionAttributes());
            log.debug("ack: {}", headers.getAck());
            log.debug("command: {}", headers.getCommand());
            log.debug("destination: {}", headers.getDestination());
            log.debug("subscriptionId: {}", headers.getSubscriptionId());
            log.debug("user: {}", headers.getUser());
        }
    }
}
