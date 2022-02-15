package com.bit.metax.exception;

import lombok.Getter;

import java.util.Map;

public class ObjectValidationException extends RuntimeException{

    @Getter
    private final Map<String, String> errors;

    public ObjectValidationException(Map<String, String> errors) {
        this.errors = errors;
    }

}
