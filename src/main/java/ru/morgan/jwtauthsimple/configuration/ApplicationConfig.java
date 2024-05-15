package ru.morgan.jwtauthsimple.configuration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import reactor.core.publisher.Mono;
import ru.morgan.jwtauthsimple.enums.UserRole;
import ru.morgan.jwtauthsimple.model.AppUser;
import ru.morgan.jwtauthsimple.repositories.AppUserRepository;

import java.time.LocalDate;

@Slf4j
@Configuration
public class ApplicationConfig {
    @Value("${admin.password}")
    private String password;

    @Bean
    public CommandLineRunner preSetup(AppUserRepository userRepository, PasswordEncoder encoder){
        return args -> {
            userRepository.findByUsername("admin").flatMap(user -> {
                log.info("user with username {} has been found in db", user.getUsername());
                return Mono.just(user);
            }).switchIfEmpty(
                    Mono.just(new AppUser()).flatMap(user -> {
                        user.setUsername("admin");
                        user.setPassword(encoder.encode(password));
                        user.setRole(UserRole.ADMIN);
                        user.setEmail("admin@security.net");
                        user.setPlacedAt(LocalDate.now());
                        return userRepository.save(user).flatMap(u -> {
                            log.info("user [{}] has been created with password [{}]", user,password);
                            return Mono.just(u);
                        });
                    })
            ).subscribe();
        };
    }
}
