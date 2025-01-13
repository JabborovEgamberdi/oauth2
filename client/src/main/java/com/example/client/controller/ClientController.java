package com.example.client.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

@Controller
public class ClientController {

    private final static String resourceServerUrl = "http://localhost:8000";

    @GetMapping("/")
    public String index() {
        return "login";
    }

    @GetMapping("/private-data")
    public String getPrivateData(
            @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User oauth2User,
            Model model
    ) {
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        RestTemplate restTemplate = new RestTemplate();
        String privateData = restTemplate.getForObject(
                resourceServerUrl + "/api/private",
                String.class,
                "Bearer " + accessToken.getTokenValue()
        );
        model.addAttribute("privateData", privateData);
        model.addAttribute("userName", oauth2User.getName());
        return privateData;
    }

}