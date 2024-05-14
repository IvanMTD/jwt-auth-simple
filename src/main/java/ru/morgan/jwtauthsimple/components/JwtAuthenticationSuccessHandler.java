package ru.morgan.jwtauthsimple.components;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    public JwtAuthenticationSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        String username = authentication.getName();
        String digitalSignature = webFilterExchange.getExchange().getRequest().getHeaders().getETag();
        log.info("digital signature information {}", digitalSignature);

        String accessToken = jwtUtil.generateAccessToken(username, digitalSignature);
        String refreshToken = jwtUtil.generateRefreshToken(username, digitalSignature);

        // Add tokens to cookies
        ResponseCookie accessCookie = ResponseCookie.from("access_token", accessToken)
                .httpOnly(true)
                .path("/")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .path("/")
                .build();

        ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
        return response.setComplete();
    }
}
