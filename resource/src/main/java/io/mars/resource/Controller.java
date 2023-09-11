package io.mars.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api")
public class Controller {

    @GetMapping("/free")
    public String freeRoute(){
        LocalDateTime time = LocalDateTime.now();
        return "[free] : |--> " + time;
    }

    @GetMapping("/protected")
    public String protectedRoute(){
        LocalDateTime time = LocalDateTime.now();
        return "[protected] : |--> " + time;
    }
}
