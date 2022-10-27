package com.artion.springboot.app.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;


public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    private AuthenticationManager authenticationManager;


    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //Igual a tener String username =  request.getParameter("username")
        String username = this.obtainUsername(request);
//        username = username != null ? username.trim() : "";
        String password = this.obtainPassword(request);
//        password = password != null ? password : "";

        if (username == null)
            username = "";

        if (password == null)
            password = "";

        username = username.trim();


        if (username != null && password != null) {
            logger.info("Username desde request parameter (form-data) " + username);
            logger.info("Password desde request parameter (form-data) " + password);
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

//        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
//        SecretKey secretKey = Keys.hmacShaKeyFor("algunaLlaveSecreta".getBytes())
//        SecretKey secretKey = new SecretKeySpec("algunaLlaveSecreta".getBytes(), SignatureAlgorithm.HS256.getJcaName());

        String username = ((User) authResult.getPrincipal()).getUsername();
        String token = Jwts.builder()
                .setSubject(username)
                .signWith(SECRET_KEY)
                .compact();

        response.addHeader("Authorization", "Bearer " + token);

        Map<String, Object> body = new HashMap<String, Object>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        body.put("mensaje", String.format("Hola %s, has iniciado sesión con éxito!", username));

        //de Map --> JSON
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }
}
