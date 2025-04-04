package com.example.client.client;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;

@HttpExchange("http://localhost:8080")
public interface HelloClient {

    @GetExchange("/")
    String getHello();

}