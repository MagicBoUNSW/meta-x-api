package com.bit.metax.service;

import com.bit.metax.dto.ChangeFullNameDto;
import com.bit.metax.model.User;

import java.util.Optional;

public interface UserService {
    Optional<User> getUserWithAuthorities();
    int enabledWebUser(String email);
    User userWithThisEmail(String email);
    String createResendToken(String previousToken);
    String createResetToken(String email);
    String createChangePassWordToken(String email);
    User resetPassword(String email, String password);
    User changeFullName(ChangeFullNameDto changeFullNameDto);
}
