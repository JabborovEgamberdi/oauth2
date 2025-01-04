package com.example.authorizationserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {

//    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/perform-login")
    public String performLoginPage() {
        return "perform-login";
    }

}