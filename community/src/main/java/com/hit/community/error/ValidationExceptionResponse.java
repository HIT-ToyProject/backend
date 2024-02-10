package com.hit.community.error;

import org.springframework.validation.BindingResult;

import java.util.List;

public record ValidationExceptionResponse(
        ErrorCode errorCode,
        List<FiledException> exceptions
) {

    public static ValidationExceptionResponse of(
            BindingResult bindingResult
    ){
        return new ValidationExceptionResponse(
                ErrorCode.VALIDATION_ERROR,
                FiledException.create(bindingResult)
        );
    }
}
