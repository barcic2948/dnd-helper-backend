package dndhelper.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import dndhelper.enums.JwtTokenTypeEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    @JsonProperty("access_token")
    private String accessToken;
    @JsonProperty("access_token_expiry")
    private int accessTokenExpiry;
    @JsonProperty("token_type")
    private JwtTokenTypeEnum tokenType;
    @JsonProperty("user_name")
    private String userName;
}