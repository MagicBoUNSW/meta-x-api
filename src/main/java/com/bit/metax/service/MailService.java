package com.bit.metax.service;

public interface MailService {

    void sendVerificationLink(String email, String content);


    String buildVerificationEmail(String name, String link);


    void sendResetPasswordLink(String email, String content);


    String buildResetPasswordEmail(String name, String link);


    void sendChangePasswordCode(String email, String content);


    String buildChangePasswordEmail(String name, String token);
}

