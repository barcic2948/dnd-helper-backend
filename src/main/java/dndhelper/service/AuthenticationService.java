package dndhelper.service;

import dndhelper.controllers.AuthResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

public interface AuthenticationService {
    AuthResponse getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response);

    AuthResponse getAccessTokenUsingRefreshToken(HttpServletRequest request);
}
