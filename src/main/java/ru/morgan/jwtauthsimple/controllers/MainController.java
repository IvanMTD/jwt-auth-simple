package ru.morgan.jwtauthsimple.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.result.view.Rendering;
import reactor.core.publisher.Mono;
import ru.morgan.jwtauthsimple.components.JWTUtil;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final JWTUtil jwtUtil;

    @GetMapping("/")
    public Mono<Rendering> mainPage(){
        return Mono.just(
                Rendering.view("template")
                        .modelAttribute("title","Main")
                        .modelAttribute("index","main-page")
                        .build()
        );
    }
}
