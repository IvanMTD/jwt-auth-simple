package ru.morgan.jwtauthsimple.components;

import io.netty.handler.codec.http.cookie.Cookie;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationConverter implements ServerAuthenticationConverter {

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        log.info("converter in work!");
        String accessToken = extractTokenFromCookie(exchange.getRequest(), "access_token");
        String refreshToken = extractTokenFromCookie(exchange.getRequest(), "refresh_token");
        log.info("access: {}", accessToken);
        log.info("refresh: {}", refreshToken);
        if(accessToken.equals("") && refreshToken.equals("")){
            return Mono.empty();
        }else{
            return Mono.just(new UsernamePasswordAuthenticationToken(accessToken, refreshToken));
        }
    }

    private String extractTokenFromCookie(ServerHttpRequest request, String cookieName) {
        HttpCookie cookie = request.getCookies().getFirst(cookieName);
        return cookie != null ? cookie.getValue() : "";
    }

}
