package dndhelper.config.security.jwt;

import dndhelper.config.security.RSAKeyRecord;
import dndhelper.config.security.user.CustomUserDetails;
import dndhelper.jpa.repository.RefreshTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@RequiredArgsConstructor
public class JwtRefreshTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtRefreshTokenFilter.class);
    private final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            logger.info("[doFilterInternal] :: Started");
            logger.info("[doFilterInternal] Filtering the Http Request: {}", request.getRequestURI());

            final String refreshToken = Arrays.stream(request.getCookies()).filter(cookie -> "refresh_token".equals(cookie.getName())).findFirst().map(Cookie::getValue).orElse(null);

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();

            if (refreshToken == null) {
                filterChain.doFilter(request, response);
                return;
            }

            final Jwt jwtToken = jwtDecoder.decode(refreshToken);
            final String username = jwtTokenUtils.getUsername(jwtToken);

            if (!username.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {

                boolean isRefreshTokenValidInDatabase = refreshTokenRepository.findByToken(jwtToken.getTokenValue())
                        .map(t -> !t.isRevoked())
                        .orElse(false);

                CustomUserDetails userDetails = jwtTokenUtils.getUserDetails(username);
                if (jwtTokenUtils.isTokenValid(jwtToken, userDetails) && isRefreshTokenValidInDatabase) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }

            logger.info("[doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        } catch (JwtValidationException e) {
            logger.error("[doFilterInternal] Exception due to: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("JWT validation failed: " + e.getMessage());
        } catch (UsernameNotFoundException e) {
            logger.error("[doFilterInternal] Exception due to: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Could not find username: " + e.getMessage());
        }
    }
}