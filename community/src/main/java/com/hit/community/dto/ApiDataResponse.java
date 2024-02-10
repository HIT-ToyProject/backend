package com.hit.community.dto;

import com.hit.community.error.ErrorCode;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

@Getter
@EqualsAndHashCode(callSuper = true)
public class ApiDataResponse<T> extends ApiErrorResponse{

    private final T data;
    private ApiDataResponse(T data) {
        super(true, ErrorCode.OK.getStatusCode().value(), ErrorCode.OK.getMessage());
        this.data = data;
    }


    public static <T> ApiDataResponse<T> of(T data){
        return new ApiDataResponse<>(data);
    }
}
