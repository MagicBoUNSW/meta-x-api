package com.bit.metax.controller;

import com.bit.metax.dto.ForgotPasswordDto;
import com.bit.metax.dto.LoginDto;
import com.bit.metax.dto.ResetPasswordDto;
import com.bit.metax.dto.UserRequestDto;
import com.bit.metax.exception.BadRequestException;
import com.bit.metax.exception.UnauthorizedException;
import com.bit.metax.model.User;
import com.bit.metax.repository.UserRepository;
import com.bit.metax.security.jwt.JWTFilter;
import com.bit.metax.security.jwt.JWTTokenProvider;
import com.bit.metax.service.AuthService;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    private static final String SOCIAL_NETWORK_GOOGLE = "google";
    private static final String SOCIAL_NETWORK_FACEBOOK = "facebook";

    public static final int PASSWORD_MIN_LENGTH =4;

    public static final int PASSWORD_MAX_LENGTH = 100;

    private AuthService authService;
    private JWTTokenProvider tokenProvider;
    private AuthenticationManagerBuilder authenticationManagerBuilder;
    private UserRepository userRepository;

    /**
     * {@code POST  /register} : register the user.
     *
     * @param user the managed user View Model.
     * @throws BadRequestException {@code 400 (Bad Request)} if the password is incorrect.
     * @throws BadRequestException {@code 400 (Bad Request)} if the email is already used.
     * @throws BadRequestException {@code 400 (Bad Request)} if the login is already used.
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @ApiOperation(value = "Creates user")
    @ApiResponses(value = {//
        @ApiResponse(code = 400, message = "Password is incorrect"),
        @ApiResponse(code = 400, message = "Email is already used"),
        @ApiResponse(code = 400, message = "Username is already used"),
        @ApiResponse(code = 403, message = "Access denied"),
        @ApiResponse(code = 422, message = "Username is already in use")})
    public String registerAccount(@ApiParam("Register User") @Valid @RequestBody UserRequestDto user) {
        if (isPasswordLengthInvalid(user.getPassword())) {
            throw new BadRequestException("Incorrect password");
        }

        return authService.registerUser(user, user.getPassword());
    }

    @PostMapping("/login")
    @ApiOperation(value = "Authenticates user and returns its JWT token.")
    @ApiResponses(value = {//
        @ApiResponse(code = 400, message = "Something went wrong"), //
        @ApiResponse(code = 422, message = "Invalid username/password supplied")})
    public ResponseEntity<JWTToken> authorize(@Valid @RequestBody LoginDto login) {

        Authentication authentication = authenticate(login);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.createToken(authentication);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JWTFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        return new ResponseEntity<>(new JWTToken(jwt), httpHeaders, HttpStatus.OK);
    }

    @GetMapping("/confirm/{token}")
    public String confirm(@PathVariable String token) {
        return authService.confirmToken(token);
    }

    @GetMapping("/resend/{previousToken}")
    public String resendToken(@PathVariable String previousToken) {return authService.resendToken(previousToken);}

    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestBody ForgotPasswordDto forgotPasswordDTO) { return authService.sendForgotPasswordToken(forgotPasswordDTO.getEmail());}

    @PutMapping("/reset-password/{token}")
    public String resetPasswordWhenUserForgot(@PathVariable String token, @RequestBody ResetPasswordDto resetPasswordDto) {
        return authService.resetPasswordWhenUserForgot(token, resetPasswordDto);
    }


    private static boolean isPasswordLengthInvalid(String password) {
        return (
            StringUtils.isEmpty(password) ||
                password.length() < PASSWORD_MIN_LENGTH ||
                password.length() > PASSWORD_MAX_LENGTH
        );
    }

    private Authentication authenticate(LoginDto login) {
        Authentication authentication;
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                login.getUsername(),
                login.getPassword()
        );
        if (StringUtils.isEmpty(login.getSocialNetwork())) {
            authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            return authentication;
        }else {

            // Social network login
            Optional<User> optUser = userRepository.findByEmail(login.getUsername());
            if(!optUser.isPresent()) throw new UnauthorizedException("Email not found!");

            User user = optUser.get();

            List<GrantedAuthority> grantedAuthorities = user.getRoles().stream().map(authority -> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());

            org.springframework.security.core.userdetails.User userDetail = new org.springframework.security.core.userdetails.User(login.getUsername(),
                    user.getPassword(),
                    grantedAuthorities);
            return new UsernamePasswordAuthenticationToken(userDetail, user.getPassword(), grantedAuthorities);
        }
    }

    /**
     * Object to return as body in JWT Authentication.
     */
    static class JWTToken {

        @JsonProperty("token")
        private String idToken;

        JWTToken(String idToken) {
            this.idToken = idToken;
        }

    }
}
