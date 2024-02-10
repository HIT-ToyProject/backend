package com.hit.community.dto;

import com.hit.community.error.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;


@Getter
@EqualsAndHashCode
@RequiredArgsConstructor
public class ApiErrorResponse{

    private final Boolean success;
    private final Integer errorCode;
    private final String message;

    public static ApiErrorResponse of(
            Boolean success,
            Integer errorCode,
            String message
    ){
        return new ApiErrorResponse(success, errorCode, message);
    }

    public static ApiErrorResponse of(
            ErrorCode errorCode
    ){
        return new ApiErrorResponse(
                false,
                errorCode.getStatusCode().value(),
                errorCode.getMessage());
    }

}
