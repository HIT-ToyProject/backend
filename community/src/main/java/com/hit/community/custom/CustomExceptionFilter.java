package com.hit.community.custom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hit.community.dto.ApiErrorResponse;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.server.Encoding;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class CustomExceptionFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        }
        catch (CustomException ex){
            sendExceptionError(response, ex.getErrorCode());

        }
        catch (Exception ex){
            throw ex;
            //sendExceptionError(response, ErrorCode.INTERNAL_SERVER);
        }
    }

    private void sendExceptionError(HttpServletResponse response, ErrorCode errorCode) throws IOException {
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
