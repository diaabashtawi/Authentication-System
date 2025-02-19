package com.bakheet.main.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class RegistrationRequest {

    @NotBlank(message = "First name filed is required")
    private String firstName;
    @NotBlank(message = "Last name filed is required")
    private String lastName;
    @Email(message = "Email invalid")
    @NotBlank(message = "Email filed is required")
    private String email;
    @Size(min = 8, message = "Password should be 8 characters long minimum")
    @NotBlank(message = "Password filed is required")
    private String password;
}
