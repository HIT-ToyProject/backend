package com.hit.community.controller.exception;

import com.hit.community.dto.ApiErrorResponse;
import com.hit.community.error.CustomException;
import com.hit.community.error.ErrorCode;
import com.hit.community.error.ValidationExceptionResponse;
import com.nimbusds.jose.shaded.gson.internal.bind.util.ISO8601Utils;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.io.IOException;
import java.util.Arrays;


@RestControllerAdvice(annotations = RestController.class)
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {


    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers,
                                                                  HttpStatusCode status,
                                                                  WebRequest request) {
        return handleExceptionInternal(ex, ValidationExceptionResponse.of(ex.getBindingResult()), request);
    }

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<Object> customException(CustomException ex, WebRequest request, HttpServletResponse response) throws IOException {
        return handleExceptionInternal(ex, ex.getErrorCode(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> exception(Exception ex, WebRequest request, HttpServletResponse response){
        ErrorCode errorCode = ErrorCode.valueOf(HttpStatus.valueOf(response.getStatus()));
        return handleExceptionInternal(ex, errorCode, request);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception ex, Object body, HttpHeaders headers, HttpStatusCode statusCode, WebRequest request) {
        return super.handleExceptionInternal(ex, body, headers, statusCode, request);
    }

    private ResponseEntity<Object> handleExceptionInternal(Exception ex, ValidationExceptionResponse body, WebRequest request) {
        return super.handleExceptionInternal(ex, body, HttpHeaders.EMPTY, body.errorCode().getStatusCode(), request);
    }

    private ResponseEntity<Object> handleExceptionInternal(Exception ex, ErrorCode errorCode,WebRequest request) {
        return handleExceptionInternal(
                ex,
                ApiErrorResponse.of(false, errorCode.getStatusCode().value(), errorCode.getMessage()),
                HttpHeaders.EMPTY,
                errorCode.getStatusCode(),
                request);
    }
}
