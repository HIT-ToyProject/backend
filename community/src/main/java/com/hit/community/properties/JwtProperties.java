package com.hit.community.properties;

import io.jsonwebtoken.security.Keys;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

public class JwtProperties {

    public static final String ACCESS_TOKEN_NAME = "Access_Token" ;
    public static final String REFRESH_TOKEN_NAME = "Refresh_Token";
    public static final String  JWT_TYPE = "Bearer ";
    public static final String AUTHORIZATION = "Authorization";
}
