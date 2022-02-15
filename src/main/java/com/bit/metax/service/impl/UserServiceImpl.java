package com.bit.metax.service.impl;

import com.bit.metax.dto.ChangeFullNameDto;
import com.bit.metax.model.ConfirmationToken;
import com.bit.metax.model.User;
import com.bit.metax.repository.ConfirmationTokenRepository;
import com.bit.metax.repository.UserRepository;
import com.bit.metax.security.SecurityUtils;
import com.bit.metax.service.UserService;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);
    private UserRepository userRepository;
    private ConfirmationTokenRepository confirmationTokenRepository;
    private PasswordEncoder passwordEncoder;

    @Override
    public Optional<User> getUserWithAuthorities() {
        logger.info("Fetching current user info");
        return userRepository.findByUsername(SecurityUtils.getCurrentUserLogin());
    }

    @Override
    public int enabledWebUser(String email) {
        return userRepository.enableUser(email);
    }

    @Override
    public User userWithThisEmail(String email) {
        User existedUser = userRepository.findUserByEmail(email);
        if (existedUser != null) {
            return existedUser;
        } else {
            throw new  IllegalStateException("This email has not been used to registered");
        }
    }

    @Override
    public String createResendToken(String previousToken) {
        ConfirmationToken existedToken = confirmationTokenRepository.findByToken(previousToken)
                .orElseThrow(() -> new IllegalStateException("Token not found"));

        User existedUser = existedToken.getUser();
        String useFor = existedToken.getUseFor();

        String newToken;
        if (useFor.equalsIgnoreCase("Verify Email")) {
            newToken = UUID.randomUUID().toString();
             ConfirmationToken confirmationToken = new ConfirmationToken(
                    newToken,
                    LocalDateTime.now(),
                    LocalDateTime.now().plusHours(3),
                    existedUser,
                    "Verify Email"
            );
            confirmationTokenRepository.save(confirmationToken);
        } else if (useFor.equalsIgnoreCase( "Reset password")) {
            newToken = createResetToken(existedUser.getEmail());
        } else {
            newToken = createChangePassWordToken(existedUser.getEmail());
        }
        return newToken;
    }

    @Override
    public String createResetToken(String email) {
        User existedUser = userWithThisEmail(email);

        String token = UUID.randomUUID().toString();
        ConfirmationToken resetToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                existedUser,
                "Reset password"
        );
        confirmationTokenRepository.save(resetToken);
        return token;
    }

    @Override
    public String createChangePassWordToken(String email) {
        User existedUser = userWithThisEmail(email);

        Random rnd = new Random();
        int number = rnd.nextInt(9999);
        String token = String.format("%04d", number);
        ConfirmationToken resetToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(2),
                existedUser,
                "Change password"
        );
        confirmationTokenRepository.save(resetToken);
        return token;
    }

    @Override
    public User resetPassword(String email, String password) {
        User webUser = userRepository.findUserByEmail(email);
        if (webUser == null) {
            throw new IllegalStateException("User with this email does not exist!");
        } else {
            String encryptedPassword = passwordEncoder.encode(password);
            webUser.setPassword(encryptedPassword);
            return userRepository.save(webUser);
        }
    }

    @Override
    public User changeFullName(ChangeFullNameDto changeFullNameDto) {
        User webUser = userRepository.findUserByEmail(changeFullNameDto.getEmail());
        if (webUser == null) {
            throw new IllegalStateException("User with this email does not exist!");
        } else {
            webUser.setFullName(changeFullNameDto.getFullName());
            return userRepository.save(webUser);
        }
    }
}
