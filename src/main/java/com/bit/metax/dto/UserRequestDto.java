package com.bit.metax.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.Instant;
import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserRequestDto {

    @Id
    private Long id;

    @NotBlank
    @Size(max = 20)
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    private String password;

    @NotNull
    private boolean activated = true;

    @Size(min = 2, max = 6)
    private String langKey;
    private String activationKey;
    private String resetKey;
    private String fullName;
    private String phone;
    private String imageUrl;
    private String socialNetwork;
    private Instant createdDate = Instant.now();

    private List<String> roles;
}
