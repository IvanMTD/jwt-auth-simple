package ru.morgan.jwtauthsimple.components;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import java.util.ArrayList;

public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JWTUtil jwtUtil;

    public JwtAuthenticationManager(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String accessToken = authentication.getCredentials().toString();
        String refreshToken = "get_refresh_token_from_cookies"; // replace with code to get refresh token from cookies

        if (jwtUtil.validateToken(accessToken)) {
            String username = jwtUtil.getUsernameFromToken(accessToken);
            return Mono.just(new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>()));
        } else if (jwtUtil.validateToken(refreshToken)) {
            String username = jwtUtil.getUsernameFromToken(refreshToken);
            String newAccessToken = jwtUtil.generateAccessToken(username, "my_app"); // replace with your digital signature
            String newRefreshToken = jwtUtil.generateRefreshToken(username, "my_app"); // replace with your digital signature

            // Add new tokens to cookies
            // ...

            return Mono.just(new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>()));
        } else {
            return Mono.empty();
        }
    }
}
