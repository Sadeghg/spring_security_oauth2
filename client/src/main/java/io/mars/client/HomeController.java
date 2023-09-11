package io.mars.client;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class HomeController {

    private final HomeClient homeClient;

    @GetMapping("/free")
    public String free() {
        String free = homeClient.freeRoute();
        return "<h1>" + free + "<h1>";
    }

    @GetMapping("/protected")
    public String authenticated() {
        String authenticated = homeClient.freeRoute();
        return "<h1>" + authenticated + "<h1>";
    }
}
