package com.example.resourceserver.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
public class ApiController {

    @GetMapping("/api/public")
    public String publicEndpoint() {
        return "This is a public endpoint.";
    }

    @PreAuthorize("hasAnyAuthority('ADMIN', 'MANAGER')")
    @GetMapping("/api/private")
    public String privateEndpoint() {
        return "This is a protected resource. Access granted!";
    }

    @GetMapping("/")
    public String home() {
        LocalDateTime time = LocalDateTime.now();
        return "Hello from the resource server! - " + time;
    }

}