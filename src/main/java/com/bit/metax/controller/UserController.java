package com.bit.metax.controller;

import com.bit.metax.dto.ChangeFullNameDto;
import com.bit.metax.dto.ChangePasswordDto;
import com.bit.metax.dto.ForgotPasswordDto;
import com.bit.metax.dto.UserResponseDto;
import com.bit.metax.exception.UnauthorizedException;
import com.bit.metax.model.User;
import com.bit.metax.service.AuthService;
import com.bit.metax.service.UserService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.Authorization;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController @AllArgsConstructor
@RequestMapping("/api/account")
public class UserController {

    private UserService userService;
    private AuthService authService;
    /**
     * {@code GET  /account} : get the current user.
     *
     * @return the current user.
     * @throws RuntimeException {@code 500 (Internal Server Error)} if the user couldn't be returned.
     */
    @GetMapping("/me")
    @ApiOperation(value = "Returns current user's data", response = UserResponseDto.class, authorizations = { @Authorization(value="apiKey") })
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Something went wrong"),
        @ApiResponse(code = 400, message = "User could was not found"),
        @ApiResponse(code = 403, message = "Access denied"),
        @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public UserResponseDto getAccount() {
        return userService
            .getUserWithAuthorities()
            .map(UserResponseDto::new)
            .orElseThrow(() -> new UnauthorizedException("User could was not found"));
    }

    @PutMapping("/reset-password")
    public String resetPassword(@RequestBody ChangePasswordDto changePasswordDto) {
        return authService.resetPassword(changePasswordDto);
    }

    @PostMapping("generate-change-password-token")
    public String generateChangePasswordToken(@RequestBody ForgotPasswordDto forgotPasswordDTO) {
        return authService.generateChangePasswordToken(forgotPasswordDTO.getEmail());
    }

    @PostMapping("/update-name")
    public User changeFullName(@RequestBody ChangeFullNameDto changeFullNameDto) {
        return authService.changeFullName(changeFullNameDto);
    }

}
