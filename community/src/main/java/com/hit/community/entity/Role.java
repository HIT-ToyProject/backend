package com.hit.community.entity;

import lombok.Getter;

@Getter
public enum Role {
    ROLE_GUEST, ROLE_ADMIN, ROLE_USER;
    public static Role checkRole(String role){
        return switch (role) {
            case "ROLE_GUEST" -> ROLE_GUEST;
            case "ROLE_ADMIN" -> ROLE_ADMIN;
            default -> ROLE_USER;
        };
    }
}
