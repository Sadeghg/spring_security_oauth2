package io.mars.client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@RequiredArgsConstructor
public class HomeController {

    private final WebClient webClient;

    @GetMapping("/test")
    public String test(){
        return "tEsT!#?$";
    }

    @GetMapping("/free")
    public String free() {
    return webClient.get()
            .uri("http://localhost:8090/api/free")
            .retrieve()
            .bodyToMono(String.class)
            .block();
    }

    @GetMapping("/protected")
    public String free(@RegisteredOAuth2AuthorizedClient("messages-client-oidc")
                           OAuth2AuthorizedClient authorizedClient) {
        return webClient.get()
                .uri("http://localhost:8090/api/protected")
                .attributes(ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }
}
