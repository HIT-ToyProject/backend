package com.hit.community.util;

import com.hit.community.entity.LoginType;
import com.hit.community.properties.JwtProperties;
import com.hit.community.dto.TokenDto;
import com.hit.community.entity.Role;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {

    private final Key SECRET;
    private final RedisTemplate<String, Object> redisBlackListTemplate;
    private JwtUtil(
            @Value("${jwt.secret}")
            String SECRET,
            @Autowired
            RedisTemplate<String, Object> redisBlackListTemplate
            ) {
        this.SECRET = Keys.hmacShaKeyFor(Base64.getEncoder().encode(SECRET.getBytes()));
        this.redisBlackListTemplate = redisBlackListTemplate;
    }

    public TokenDto getToken(String email, Role role, LoginType type){
        long tokenPeriod = 1000L * 60L * 30L; // 30분
        long refreshPeriod =  1000L * 60L * 60L * 24L * 14; // 2주
        String accessToken = createAccessToken(email,role,type, tokenPeriod);
        String refreshToken = createRefreshToken(email,role,type, refreshPeriod);
        return TokenDto.of(accessToken, refreshToken, email);
    }

    private String createAccessToken(String email,Role role,LoginType type, long tokenPeriod) {
        Date now = new Date();
        return Jwts.builder().setSubject(JwtProperties.ACCESS_TOKEN_NAME)
                .setHeader(createHeader())
                .setClaims(createClaims(email, role, type))
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenPeriod))
                .signWith(SECRET, SignatureAlgorithm.HS512)
                .compact();
    }

    private Claims createClaims(String email, Role role, LoginType type) {
        Claims claims = Jwts.claims();
        claims.put("email", email);
        claims.put("role", role);
        claims.put("type", type);
        return claims;
    }

    private String createRefreshToken(String email,Role role,LoginType type,long tokenPeriod) {
        Date now = new Date();
        return Jwts.builder().setSubject(JwtProperties.REFRESH_TOKEN_NAME)
                .setHeader(createHeader())
                .setClaims(createClaims(email, role, type))
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenPeriod))
                .signWith(SECRET, SignatureAlgorithm.HS512)
                .compact();
    }

    private Map<String, Object> createHeader() {
        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "HS256");
        return header;
    }

    private Long getExpired(String token){
        Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(SECRET)
                .build()
                .parseClaimsJws(token);
        return claims.getBody()
                .getExpiration()
                .getTime();
    }

    public String getEmail(String token){
        return (String) Jwts.parserBuilder().setSigningKey(SECRET)
                .build().parseClaimsJws(token).getBody().get("email");
    }
    public Role getRole(String token) {
        String role = (String)Jwts.parserBuilder().setSigningKey(SECRET).build()
                .parseClaimsJws(token).getBody().get("role");
        return Role.checkRole(role);
    }

    public LoginType getLoginType(String token) {
        String type = (String) Jwts.parserBuilder().setSigningKey(SECRET).build()
                .parseClaimsJws(token).getBody().get("type");
        return LoginType.checkType(type);
    }

    public void addBlackList(String token){
        redisBlackListTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(String.class));
        redisBlackListTemplate.opsForValue().set(
                token,
                "accessToken",
                getExpired(token),
                TimeUnit.MILLISECONDS);
    }

    private boolean hasKeyBlackList(String token){
        return Boolean.TRUE.equals(redisBlackListTemplate.hasKey(token));
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(SECRET).build().parseClaimsJws(token);

            if(hasKeyBlackList(token)){
                throw new CustomException(ErrorCode.ALREADY_LOGGED_OUT_USER);
            }
            return true;
        } catch (SecurityException | MalformedJwtException |IllegalArgumentException e) {
            throw new CustomException(ErrorCode.INVALID_TOKEN);
        } catch (ExpiredJwtException e) {
            throw new CustomException(ErrorCode.EXPIRED_TOKEN);
        } catch (UnsupportedJwtException e) {
            throw new CustomException(ErrorCode.UNSUPPORTED_TOKEN);
        }

    }


}
