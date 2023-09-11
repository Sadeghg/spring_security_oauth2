package io.mars.server;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;


@Configuration
public class UserStoreConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
        UserDetails admin = User.withUsername("Admin")
                .password("123").roles("ADMIN")
                .authorities("WRITE", "READ")
                .build();
        UserDetails user = User.withUsername("User")
                .password("123").roles("USER")
                .authorities("READ")
                .build();
        userDetailsManager.createUser(admin);
        userDetailsManager.createUser(user);
        return userDetailsManager;
    }
}
