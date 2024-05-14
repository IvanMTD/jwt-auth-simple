package ru.morgan.jwtauthsimple.services;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import ru.morgan.jwtauthsimple.repositories.AppUserRepository;

@Service
@RequiredArgsConstructor
public class UserService implements ReactiveUserDetailsService {
    private final AppUserRepository appUserRepository;

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }
}
