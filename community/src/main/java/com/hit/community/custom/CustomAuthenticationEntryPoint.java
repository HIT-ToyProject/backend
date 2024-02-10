package com.hit.community.custom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hit.community.dto.ApiErrorResponse;
import com.hit.community.error.ErrorCode;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.server.Encoding;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {


        ErrorCode jwtFilterErrorCode = (ErrorCode) request.getAttribute("exception");

        ErrorCode errorCode = getErrorCode(authException, jwtFilterErrorCode);
        ApiErrorResponse apiErrorResponse =
                ApiErrorResponse.of(false, errorCode.getStatusCode().value(), errorCode.getMessage());
        response.setCharacterEncoding(Encoding.DEFAULT_CHARSET.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(errorCode.getStatusCode().value());
        response.getWriter().write(objectMapper.writeValueAsString(apiErrorResponse));
        response.getWriter().flush();
        response.getWriter().close();
    }

    private static ErrorCode getErrorCode(AuthenticationException authException, ErrorCode jwtFilterErrorCode) {
        ErrorCode errorCode;
        if(jwtFilterErrorCode != null){
          errorCode = jwtFilterErrorCode;
        } else if (authException instanceof InsufficientAuthenticationException) {
            errorCode = ErrorCode.NOT_USER;
        } else if(authException instanceof UsernameNotFoundException){
            errorCode = ErrorCode.USER_NOT_FOUND;
        }
        else if(authException instanceof BadCredentialsException){
            errorCode = ErrorCode.EMAIL_OR_PASSWORD_NOT_FOUND;
        } else if (authException instanceof AuthenticationServiceException) {
            errorCode = ErrorCode.EMAIL_OR_PASSWORD_NOT_FOUND;
        } else {
            errorCode = ErrorCode.INTERNAL_SERVER;
        }
        return errorCode;
    }
}
