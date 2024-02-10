package com.hit.community.entity;

public enum LoginType {
    GENERAL, NAVER, KAKAO, GOOGLE;

    public static LoginType checkType(String type) {
        return switch (type) {
            case "GENERAL" -> GENERAL;
            case "NAVER" -> NAVER;
            case "KAKAO" -> KAKAO;
            default -> GOOGLE;
        };
    }
}
