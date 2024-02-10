package com.hit.community.custom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hit.community.dto.ApiDataResponse;
import com.hit.community.dto.ApiErrorResponse;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.server.Encoding;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.util.EncodingUtils;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        ErrorCode errorCode = ErrorCode.ACCESS_DENIED_ERROR;
        ApiErrorResponse apiErrorResponse =
                ApiErrorResponse.of(false, errorCode.getStatusCode().value(), errorCode.getMessage());
        response.setCharacterEncoding(Encoding.DEFAULT_CHARSET.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(errorCode.getStatusCode().value());
        response.getWriter().write(objectMapper.writeValueAsString(apiErrorResponse));
        response.getWriter().flush();
        response.getWriter().close();
    }
}
