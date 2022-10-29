package com.artion.springboot.app.auth.filter;

import com.artion.springboot.app.auth.service.JWTService;
import com.artion.springboot.app.auth.service.JWTServiceImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    JWTService jwtService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        super(authenticationManager);
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader(JWTServiceImpl.HEADER_STRING);

        if (!requiresAuthentication(header)) {
            chain.doFilter(request, response);
            return;
        }

        //Iniciar sesión del usuario usando el token
        UsernamePasswordAuthenticationToken authentication = null;
        if (jwtService.validate(header))
            authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null, jwtService.getRoles(header));


        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    protected boolean requiresAuthentication(String header){
        if (header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
            return false;
        }
        return true;
    }
}
