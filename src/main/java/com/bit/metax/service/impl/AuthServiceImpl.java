package com.bit.metax.service.impl;

import com.bit.metax.dto.ChangeFullNameDto;
import com.bit.metax.dto.ChangePasswordDto;
import com.bit.metax.dto.ResetPasswordDto;
import com.bit.metax.dto.UserRequestDto;
import com.bit.metax.exception.BadRequestException;
import com.bit.metax.exception.UnauthorizedException;
import com.bit.metax.model.ConfirmationToken;
import com.bit.metax.model.Role;
import com.bit.metax.model.User;
import com.bit.metax.repository.ConfirmationTokenRepository;
import com.bit.metax.repository.UserRepository;
import com.bit.metax.service.AuthService;
import com.bit.metax.service.MailService;
import com.bit.metax.service.UserService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.thymeleaf.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final Logger logger = LoggerFactory.getLogger(AuthService.class);
    public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private ConfirmationTokenRepository confirmationTokenRepository;
    private UserService userService;
    private MailService mailService;

    @Override
    public String registerUser(UserRequestDto userDTO, String password) {
        userRepository
            .findByUsername(userDTO.getUsername().toLowerCase())
            .ifPresent(user -> {
                throw new UnauthorizedException("Login name already used!");
            });

        userRepository
            .findByEmail(userDTO.getEmail().toLowerCase())
            .ifPresent(user -> {
                throw new UnauthorizedException("Email is already in use!");
            });

        User newUser = new User();

        //user login by google or facebook
        if(userDTO.getSocialNetwork() == null){
            newUser.setUsername(userDTO.getUsername().toLowerCase());
            newUser.setPassword(passwordEncoder.encode(password));
            newUser.setActivated(false);
        }else {
            if (userDTO.getEmail() != null) newUser.setUsername(userDTO.getEmail().toLowerCase());
            newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));
            newUser.setFullName(userDTO.getFullName());
            newUser.setActivated(true);
            newUser.setImageUrl(userDTO.getImageUrl());
        }

        if (userDTO.getEmail() != null) {
            newUser.setEmail(userDTO.getEmail().toLowerCase());
        }
        List<String> roles = new ArrayList<>();
        roles.add(Role.ROLE_FREE_MEMBER.getAuthority());
        newUser.setRoles(roles);

        userRepository.save(newUser);

        if (userDTO.getSocialNetwork() == null) {
            String token = UUID.randomUUID().toString();
            ConfirmationToken confirmationToken = new ConfirmationToken(
                    token,
                    LocalDateTime.now(),
                    LocalDateTime.now().plusHours(3),
                    newUser,
                    "Verify Email"
            );
            confirmationTokenRepository.save(confirmationToken);
            String link = "https://metax-client.benit.io/auth/activate-account/" + token;
            mailService.sendVerificationLink(userDTO.getEmail(), mailService.buildVerificationEmail(userDTO.getUsername(), link));
            logger.info("Created Information for User: {}", newUser);
            return token;
        }
        return "Register by social media successfully!";
    }

    @Override @Transactional
    public String confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        if (confirmationToken.getUseFor().equalsIgnoreCase("Verify Email")) {
            if (confirmationToken.getConfirmedAt() != null) {
                return "This email has already been confirmed";
            }

            LocalDateTime expiresAt = confirmationToken.getExpiresAt();

            if (expiresAt.isBefore(LocalDateTime.now())) {
                return "Your token has been expired";
            }

            confirmationTokenRepository.updatedConfirmedAt(token, LocalDateTime.now());
            userService.enabledWebUser(confirmationToken.getUser().getEmail());
            return "Thank you for your registration. Your email has been verified successfully!";
        }else {
            throw new BadRequestException("Wrong token!");
        }
    }

    @Override
    public String resendToken(String previousToken) {
        ConfirmationToken previousConfirmationToken = confirmationTokenRepository.findConfirmationTokenByToken(previousToken);
        LocalDateTime expiresAt = previousConfirmationToken.getExpiresAt();
        LocalDateTime confirmedAt = previousConfirmationToken.getConfirmedAt();
        User existedUser = confirmationTokenRepository.findByToken(previousToken).get().getUser();

        String newToken;
        if (expiresAt.isBefore(LocalDateTime.now()) && confirmedAt == null) {
            newToken = userService.createResendToken(previousToken);
        } else {
            newToken = previousToken;
        }

        if (previousConfirmationToken.getUseFor().equalsIgnoreCase("Verify Email")) {
            String link = "https://metax-client.benit.io/auth/activate-account/" + newToken;
            mailService.sendVerificationLink(existedUser.getEmail(), mailService.buildVerificationEmail(existedUser.getUsername(), link));
            return newToken;
        } else if (previousConfirmationToken.getUseFor().equalsIgnoreCase("Reset password")) {
            sendForgotPasswordToken(existedUser.getEmail());
            return newToken;
        } else {
            generateChangePasswordToken(existedUser.getEmail());
            return newToken;
        }
    }

    @Override
    public String sendForgotPasswordToken(String email) {

        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(email);
        boolean isValidEmail = matcher.find();
        if(!isValidEmail) {
            throw new BadRequestException("Email not valid");
        }

        User UserWithEmail = userService.userWithThisEmail(email);
        String resetToken = userService.createResetToken(email);
        mailService.sendResetPasswordLink(email, mailService.buildResetPasswordEmail(UserWithEmail.getUsername(), resetToken));

        return resetToken;
    }

    @Override @Transactional
    public String resetPasswordWhenUserForgot(String token, ResetPasswordDto resetPasswordDto) {
        ConfirmationToken resetToken = confirmationTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        if (resetToken.getUseFor().equalsIgnoreCase("Reset password")) {
            LocalDateTime expiresAt = resetToken.getExpiresAt();
            if (expiresAt.isBefore(LocalDateTime.now())) {
                throw new IllegalStateException("Token expired");
            }

            confirmationTokenRepository.updatedConfirmedAt(token, LocalDateTime.now());
            userService.resetPassword(resetPasswordDto.getEmail(), resetPasswordDto.getPassword());
            return "Password reset successful!";
        } else {
            throw new BadRequestException("Wrong token!");
        }
    }

    @Override
    public String generateChangePasswordToken(String email) {
        String token = userService.createChangePassWordToken(email);
        User existedUser = userService.userWithThisEmail(email);
        mailService.sendChangePasswordCode(email, mailService.buildChangePasswordEmail(existedUser.getUsername(), token));
        return "The confirmation token has been sent to your email";
    }

    @Override @Transactional
    public String resetPassword(ChangePasswordDto changePasswordDto) {
        User existedUser = userService.userWithThisEmail(changePasswordDto.getEmail());
        ConfirmationToken confirmationToken = confirmationTokenRepository.findByToken(changePasswordDto.getToken()).get();
        if (confirmationToken ==  null) {
            throw new BadRequestException("Token not found");
        } else {
            if (confirmationToken.getUseFor().equalsIgnoreCase("Change password")) {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        existedUser.getUsername(),
                        changePasswordDto.getRecentPassword()
                );
                if (authenticationToken != null){
                    userService.resetPassword(changePasswordDto.getEmail(), changePasswordDto.getNewPassword());
                    return "You have changed your password successfully!";
                } else {
                    throw new BadRequestException("Wrong password!");
                }
            } else {
                throw new BadRequestException("Wrong token");
            }
        }
    }

    @Override
    public User changeFullName(ChangeFullNameDto changeFullNameDto) {
        return userService.changeFullName(changeFullNameDto);
    }

}

