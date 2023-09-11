package io.mars.client;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.service.annotation.HttpExchange;

@HttpExchange("http://localhost:8090")
public interface HomeClient {

    @GetMapping("/api/free")
    public String freeRoute();

    @GetMapping("/api/protected")
    public String protectedRoute();
}
