package com.example.authorizationserver.controller;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/")
public class UserController {


    @GetMapping("/auth_server")
    public String response() {
        return "Hello World!";
    }

//    @GetMapping("/.well-known/jwks.json")
//    public Map<String, Object> getJwkSet() {
//        return jwkSet.toJSONObject();
//    }

}