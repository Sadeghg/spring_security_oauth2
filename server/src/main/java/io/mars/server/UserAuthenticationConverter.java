package io.mars.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class UserAuthenticationConverter implements AuthenticationConverter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public Authentication convert(HttpServletRequest request) {
        UserDto user = null;
        try{
            user = MAPPER.readValue(request.getInputStream(), UserDto.class);
        }catch (IOException e){
            return null;
        }
        return UsernamePasswordAuthenticationToken.unauthenticated(user.getLogin(), user.getPassword());
    }
}
