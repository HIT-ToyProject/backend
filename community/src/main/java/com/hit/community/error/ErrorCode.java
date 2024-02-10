package com.hit.community.error;

import io.jsonwebtoken.lang.Strings;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    OK(HttpStatus.OK, "Success"),

    BAD_REQUEST(HttpStatus.BAD_REQUEST, "잘못된 요청입니다."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "존재하지 않는 회원입니다."),
    BAD_CREDENTIALS(HttpStatus.BAD_REQUEST, "이메일 또는 비밀번호가 일치하지 않습니다."),
    UN_SUPPORTED_ENCODING(HttpStatus.BAD_REQUEST,"지원되지 않는 문자 형식입니다."),
    ALREADY_LOGGED_IN_USER(HttpStatus.BAD_REQUEST, "이미 로그인된 회원입니다."),
    ALREADY_EXISTING_USER(HttpStatus.BAD_REQUEST, "이미 존재하는 회원입니다."),
    CONFIRM_CODE_MISMATCH(HttpStatus.BAD_REQUEST, "인증코드가 일치하지 않습니다."),
    EMAIL_OR_PASSWORD_NOT_FOUND(HttpStatus.NOT_FOUND, "잘못된 이메일 또는 비밀번호입니다."),
    CONFIRM_CODE_NOT_EXISTS(HttpStatus.INTERNAL_SERVER_ERROR, "인증 코드 오류입니다. 나중에 다시 시도해 주세요."),
    INVALID_TOKEN(HttpStatus.BAD_REQUEST, "토큰 정보가 올바르지 않습니다."),
    EXPIRED_TOKEN(HttpStatus.BAD_REQUEST, "만료된 토큰 정보입니다."),
    NO_EMAIL_OR_TOKEN(HttpStatus.BAD_REQUEST, "이미 로그아웃 된 회원입니다."),
    NOT_EXIST_AUTHORIZATION(HttpStatus.BAD_REQUEST, "권한이 존재하지 않습니다."),
    NOT_EXIST_TOKEN(HttpStatus.BAD_REQUEST, "토큰이 존재하지 않습니다."),
    UNSUPPORTED_TOKEN(HttpStatus.BAD_REQUEST, "지원되지 않는 토큰 정보입니다."),
    ALREADY_LOGGED_OUT_USER(HttpStatus.BAD_REQUEST, "이미 로그아웃 된 회원입니다."),
    HTTP_STATUS_NULL(HttpStatus.INTERNAL_SERVER_ERROR, "Http Status is Null"),
    VALIDATION_ERROR(HttpStatus.BAD_REQUEST,"검증 오류입니다."),
    ACCESS_DENIED_ERROR(HttpStatus.BAD_REQUEST, "접근 권한이 없습니다."),
    AUTHENTICATION_ERROR(HttpStatus.BAD_REQUEST, "인증 오류입니다."),
    NOT_USER(HttpStatus.BAD_REQUEST, "로그인 후 이용해주세요." ),


    MESSAGING(HttpStatus.INTERNAL_SERVER_ERROR, "이메일 전송에 실패했습니다. 나중에 다시 시도해 주세요."),
    NO_SUCH_ALGORITHM(HttpStatus.INTERNAL_SERVER_ERROR,"보안 처리 중 오류가 발생했습니다. 나중에 다시 시도해 주세요."),
    INTERNAL_SERVER(HttpStatus.INTERNAL_SERVER_ERROR, "일시적인 오류입니다. 잠시 후 다시 시도해주세요.");


    private final HttpStatusCode statusCode;
    private final String message;


    public static ErrorCode valueOf(HttpStatusCode httpStatus){

        if(httpStatus == null) {throw new CustomException(ErrorCode.HTTP_STATUS_NULL);}

        return Arrays.stream(values())
                .filter(errorCode -> errorCode.statusCode == httpStatus)
                .findFirst()
                .orElseGet(() ->{
                    if(httpStatus.is4xxClientError()) {return ErrorCode.BAD_REQUEST;}
                    else {return ErrorCode.INTERNAL_SERVER;}

                });
    }

    public String getMessage(String message) {
        if(Strings.hasText(message)){
            return message;
        }
        return this.getMessage();
    }
}
