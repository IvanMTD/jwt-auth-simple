package ru.morgan.jwtauthsimple.enums;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public enum UserRole {
    ADMIN("Админ"),
    USER("Пользователь");

    private final String title;

    UserRole(String title){
        this.title = title;
    }

    public String getTitle() {
        return title;
    }
}
