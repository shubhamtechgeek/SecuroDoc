package com.application.SecuroDoc.DTO;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class QrCodeRequest {

    @NotEmpty(message = "User ID cannot be empty or null")
    private String userId;
    @NotEmpty(message = "LQR code cannot be empty or null")
    private String qrCode;

}
