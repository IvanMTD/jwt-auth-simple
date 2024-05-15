/*
package ru.morgan.jwtauthsimple.components;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Component
public class SessionCookieWebFilter implements WebFilter {

    private static final String SESSION_COOKIE_NAME = "MySessionCookie";
    private static final int SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("session cookie web filter in work!");
        ResponseCookie sessionCookie = exchange.getResponse().getCookies().toSingleValueMap().get("SESSION");
        for(String key : exchange.getResponse().getCookies().toSingleValueMap().keySet()){
            log.info("cookie name: " + key);
        }

                    */
/*.entrySet()
                    .stream()
                    .filter(entry -> SESSION_COOKIE_NAME.equals(entry.getKey()))
                    .map(Map.Entry::getValue)
                    .findFirst()
                    .orElse(null);*//*


        if (sessionCookie != null) {
            log.info("session cookie [{}]",sessionCookie.toString());
            ResponseCookie newSessionCookie = ResponseCookie.from(SESSION_COOKIE_NAME, sessionCookie.getValue())
                    .maxAge(SESSION_COOKIE_MAX_AGE)
                    .httpOnly(true)
                    .path("/")
                    .build();

            exchange.getResponse().addCookie(newSessionCookie);
        }else{
            log.info("session cookie is null");
        }

        return chain.filter(exchange);
    }
}*/
