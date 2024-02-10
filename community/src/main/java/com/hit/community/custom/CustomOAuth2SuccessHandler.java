package com.hit.community.custom;

import com.hit.community.entity.LoginType;
import com.hit.community.entity.RefreshToken;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import com.hit.community.repository.RefreshTokenRepository;
import com.hit.community.util.CookieUtil;
import com.hit.community.properties.JwtProperties;
import com.hit.community.util.JwtUtil;
import com.hit.community.dto.TokenDto;
import com.hit.community.entity.Role;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
@Component
public class CustomOAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getEmail();
        Role role = oAuth2User.getRole();
        LoginType type = oAuth2User.getType();
        clearAuthenticationAttributes(request);

        if(role == Role.ROLE_GUEST){
            sendSignUpNewUser(request, response, email, type);
        }else{
            createTokenAndLonginSuccess(request, response, email, role, type);
        }
    }
    private void saveRefreshToken(TokenDto tokenDto) {
        boolean isLoginUser = refreshTokenRepository.existsByRefreshToken(tokenDto.refreshToken());
        if(isLoginUser){
            throw new CustomException(ErrorCode.ALREADY_LOGGED_IN_USER);
        }
            RefreshToken refreshToken = tokenDto.toRefreshTokenEntity();
            refreshTokenRepository.save(refreshToken);

    }
    private void createTokenAndLonginSuccess(HttpServletRequest request, HttpServletResponse response,
                                             String email, Role role, LoginType type) throws IOException {
        TokenDto tokenDto = jwtUtil.getToken(email, role, type);
        saveRefreshToken(tokenDto);
        CookieUtil.addCookies(response,JwtProperties.REFRESH_TOKEN_NAME, tokenDto.refreshToken());

        getRedirect(
                UriComponentsBuilder.fromPath("/")
                        .build(),request, response);
    }

    private void sendSignUpNewUser(HttpServletRequest request, HttpServletResponse response, String email, LoginType type) throws IOException {
        getRedirect(UriComponentsBuilder
                .fromPath("/signUp")
                .queryParam("email", email)
                .queryParam("type", type.name())
                .build()
                .expand(email), request, response);
    }

    private void getRedirect(UriComponents uriComponents, HttpServletRequest request, HttpServletResponse response) throws IOException {
        String targetUri = uriComponents
                .encode(StandardCharsets.UTF_8)
                .toUriString();
        getRedirectStrategy().sendRedirect(request, response, targetUri);
    }


}

