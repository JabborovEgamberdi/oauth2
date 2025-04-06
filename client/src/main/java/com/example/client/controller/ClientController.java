package com.example.client.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@Controller
@RestController
public class ClientController {

    private final static String resourceServerUrl = "http://localhost:8080";
    private final AppService appService;
//    private final HelloClient helloClient;

    public ClientController(AppService appService) {
        this.appService = appService;
    }

//    private final OAuth2AuthorizedClientManager clientManager;
//
//    public ClientController(OAuth2AuthorizedClientManager clientManager) {
//        this.clientManager = clientManager;
//    }

    @GetMapping("/token")
    public String token(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
                .withClientRegistrationId("1")
                .principal("client")
                .build();
//        var client = clientManager.authorize(request);
//        assert client != null;
        return authorizedClient.getAccessToken().getTokenValue();
    }

    @GetMapping("/auth_server")
    public String getPrivateData(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                                 @AuthenticationPrincipal OAuth2User oauth2User,
                                 Model model) {
//        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
//                .withClientRegistrationId("auth-server")
//                .principal("client")
//                .build();
//        var client = clientManager.authorize(request);
//        assert client != null;
//        return client.getAccessToken().getTokenValue();
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

    @GetMapping("/")
    public ResponseEntity<String> getPublicData() {
        return ResponseEntity.ok("Public data");
    }

    @GetMapping("/private-data")
    public ResponseEntity<String> getPrivateData() {
        return ResponseEntity.ok(appService.getJwtToken());
    }

//    @GetMapping("/hello")
//    public ResponseEntity<String> sayHello () {
//        return ResponseEntity.ok(helloClient.getHello());
//    }

    @GetMapping("/login")
    public String login() {
        return "redirect:/oauth2/authorization/auth-server";
    }


}