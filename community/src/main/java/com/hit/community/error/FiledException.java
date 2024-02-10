package com.hit.community.error;

import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.util.List;
import java.util.stream.Collectors;

public record FiledException(
        String filed,
        String value,
        String reason
) {
    private static FiledException of(
            String filed,
            String value,
            String reason
    ){
        return new FiledException(filed, value, reason);
    }

    public static List<FiledException> create(BindingResult bindingResult) {
        List<FieldError> fieldErrors = bindingResult.getFieldErrors();
        return fieldErrors.stream()
                .map(error->
                    FiledException.of(
                            error.getField(),
                            error.getRejectedValue() == null ? null : error.getRejectedValue().toString(),
                            error.getDefaultMessage()
                    )).collect(Collectors.toList());
    }
}
