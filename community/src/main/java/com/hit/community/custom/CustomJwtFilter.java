package com.hit.community.custom;

import com.hit.community.entity.Role;
import com.hit.community.util.JwtUtil;
import io.jsonwebtoken.lang.Strings;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class CustomJwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

            String token = getParseJwt(request);
            if (token != null && jwtUtil.validateToken(token)) {
                String email = jwtUtil.getEmail(token);
                Role role = jwtUtil.getRole(token);
                UsernamePasswordAuthenticationToken authenticated =
                        UsernamePasswordAuthenticationToken.authenticated(email, "",
                                List.of(new SimpleGrantedAuthority(role.name())));
                SecurityContextHolder.getContext().setAuthentication(authenticated);
            }
            filterChain.doFilter(request, response);
    }

    private static String getParseJwt(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(Strings.hasText(token)  && token.startsWith("Bearer ")){
            return token.substring(7);
        }
        return null;
    }
}
