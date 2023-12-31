package io.mars.server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

@Configuration
public class ClientStoreConfig {


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient projectManagement = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("project-management")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("https://oidcdebugger.com/debug")

//                .redirectUri("https://oauthdebugger.com/debug")
                .redirectUri("https://springone.io/authorized")
                .scope(OidcScopes.OPENID)
                .scope("read")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
                .build();
        return new InMemoryRegisteredClientRepository(projectManagement);
    }

}
