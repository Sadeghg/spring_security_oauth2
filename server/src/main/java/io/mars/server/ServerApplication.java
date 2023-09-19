package io.mars.server;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.Customizer;

@SpringBootApplication
public class ServerApplication{

    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
    }

}
