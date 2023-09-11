package io.mars.server;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Enumeration;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityLogFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        LocalDateTime date = LocalDateTime.now();
        System.err.println("LogFilter: " + date + " - " + request.getLocalAddr() + ":" + request.getLocalPort() + request.getServletPath());
        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()){
            String header = headers.nextElement();
            System.err.println("\tHeader: " + header +  ":" + request.getHeader(header));
        }

        System.err.println("\n\n");
        filterChain.doFilter(request, response);
    }
}
