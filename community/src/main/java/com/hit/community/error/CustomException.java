package com.hit.community.error;

import lombok.Getter;

import java.security.NoSuchAlgorithmException;

@Getter
public class CustomException extends RuntimeException{

    private ErrorCode errorCode;
    public CustomException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }



}
