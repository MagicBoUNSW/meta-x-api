package com.bit.metax.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.io.File;

@ResponseStatus(value = HttpStatus.INTERNAL_SERVER_ERROR)
public class ResourseException extends RuntimeException {
    public ResourseException(String message) {
        super(message);
    }

    public ResourseException(String message, File file) {
        super(message);
        file.delete();
    }

}
