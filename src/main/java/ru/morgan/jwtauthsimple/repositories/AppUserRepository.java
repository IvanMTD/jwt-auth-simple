package ru.morgan.jwtauthsimple.repositories;

import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;
import ru.morgan.jwtauthsimple.model.AppUser;

public interface AppUserRepository extends ReactiveCrudRepository<AppUser,Long> {
    Mono<UserDetails> findByUsername(String username);
}
