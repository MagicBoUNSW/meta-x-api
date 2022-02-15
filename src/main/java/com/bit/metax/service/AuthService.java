package com.bit.metax.service;

import com.bit.metax.dto.ChangeFullNameDto;
import com.bit.metax.dto.ChangePasswordDto;
import com.bit.metax.dto.ResetPasswordDto;
import com.bit.metax.dto.UserRequestDto;
import com.bit.metax.model.User;
import org.springframework.transaction.annotation.Transactional;

public interface AuthService {
    String registerUser(UserRequestDto userDTO, String password);

    @Transactional
    String confirmToken(String token);

    String resendToken(String previousToken);

    String sendForgotPasswordToken(String email);

    String generateChangePasswordToken(String email);

    @Transactional
    String resetPasswordWhenUserForgot(String token, ResetPasswordDto resetPasswordDto);

    @Transactional
    String resetPassword(ChangePasswordDto changePasswordDto);

    @Transactional
    User changeFullName(ChangeFullNameDto changeFullNameDto);
}
