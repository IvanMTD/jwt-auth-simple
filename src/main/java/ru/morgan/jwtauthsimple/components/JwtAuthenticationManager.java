package ru.morgan.jwtauthsimple.components;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.morgan.jwtauthsimple.model.AppUser;
import ru.morgan.jwtauthsimple.services.UserService;

import java.util.Collection;
import java.util.Collections;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationManager implements ReactiveAuthenticationManager {

    private final JWTUtil jwtUtil;
    private final UserService userService;
    private final PasswordEncoder encoder;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        log.info("manager in work!");
        String accessToken = authentication.getPrincipal().toString();
        String refreshToken = authentication.getCredentials().toString();
        log.info("access: {}", accessToken);
        log.info("refresh: {}", refreshToken);

        if(jwtUtil.validateToken(accessToken)){
            log.info("access validation successful [{}]", accessToken);
            return userService.findByUsername(jwtUtil.getUsernameFromToken(accessToken)).flatMap(user -> {
                log.info("user in token [{}]",user);
                return Mono.just(new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities()));
            });
        }else if(jwtUtil.validateToken(refreshToken)){
            log.info("refresh validation successful [{}]", refreshToken);
            return Mono.deferContextual(contextView -> {
                ServerWebExchange exchange = contextView.get(ServerWebExchange.class);
                return userService.findByUsername(jwtUtil.getUsernameFromToken(refreshToken)).flatMap(user -> {
                    String username = user.getUsername();
                    String digitalSignature = exchange.getRequest().getHeaders().getETag();
                    String newAccessToken = jwtUtil.generateAccessToken(username, digitalSignature);
                    String newRefreshToken = jwtUtil.generateRefreshToken(username, digitalSignature);
                    ResponseCookie accessCookie = ResponseCookie.from("access_token", newAccessToken)
                            .httpOnly(true)
                            .path("/")
                            .build();
                    ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", newRefreshToken)
                            .httpOnly(true)
                            .path("/")
                            .build();

                    exchange.getResponse().addCookie(accessCookie);
                    exchange.getResponse().addCookie(refreshCookie);
                    return Mono.just(new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities()));
                }).switchIfEmpty(Mono.error(new BadCredentialsException("Authentication failed")));
            });
        }else{
            String username = authentication.getPrincipal().toString();
            String password = authentication.getCredentials().toString();
            return userService.findByUsername(username).flatMap(user -> {
                if(encoder.matches(password,user.getPassword())){
                    log.info("found user [{}]",user);
                    return Mono.just(new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities()));
                } else{
                    return Mono.error(new BadCredentialsException("Authentication failed"));
                }
            }).cast(Authentication.class).switchIfEmpty(Mono.error(new BadCredentialsException("Authentication failed")));
        }
    }
}
