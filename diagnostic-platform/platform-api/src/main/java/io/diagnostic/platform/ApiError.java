package io.diagnostic.platform;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.Map;

final class ApiError extends RuntimeException {
    final HttpStatus status;
    final String code;

    ApiError(HttpStatus status, String code) {
        super(code);
        this.status = status;
        this.code = code;
    }

    static ApiError forbidden() {
        return new ApiError(HttpStatus.FORBIDDEN, "FORBIDDEN");
    }

    static ApiError conflict(String code) {
        return new ApiError(HttpStatus.CONFLICT, code);
    }

    static ApiError missing() {
        return new ApiError(HttpStatus.NOT_FOUND, "NOT_FOUND");
    }

    static ApiError invalid(String code) {
        return new ApiError(HttpStatus.BAD_REQUEST, code);
    }
}

@RestControllerAdvice
class ApiErrors {
    @ExceptionHandler(ApiError.class)
    ResponseEntity<Map<String, String>> applicationError(ApiError error) {
        return ResponseEntity.status(error.status).body(Map.of("code", error.code));
    }

    @ExceptionHandler(org.springframework.dao.DuplicateKeyException.class)
    ResponseEntity<Map<String, String>> duplicate() {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "DUPLICATE_RECORD"));
    }
}
