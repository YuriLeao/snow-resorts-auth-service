package com.snowresorts.auth.infrastructure.user;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.ProfileBootstrap;
import com.snowresorts.security.error.BadRequestException;
import com.snowresorts.security.error.ConflictException;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

@Component
public class RestProfileBootstrapClient implements ProfileBootstrap {

    private static final Logger log = LoggerFactory.getLogger(RestProfileBootstrapClient.class);
    private static final String INTERNAL_PROFILES_PATH = "/snow-resort-service/v1/users/internal/profiles";
    private static final String INTERNAL_SECRET_HEADER = "X-Internal-Secret";

    private final RestClient restClient;
    private final String internalApiSecret;

    public RestProfileBootstrapClient(RestClient userServiceRestClient, AuthTokenProperties properties) {
        this.restClient = userServiceRestClient;
        this.internalApiSecret = properties.internalApiSecret();
    }

    @Override
    public void ensureUsernameAvailable(String username) {
        try {
            restClient.get()
                    .uri("/snow-resort-service/v1/users/internal/usernames/{username}/available", username)
                    .header(INTERNAL_SECRET_HEADER, internalApiSecret)
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientResponseException ex) {
            throw mapUsernameCheckFailure(ex);
        } catch (RestClientException ex) {
            log.error("Failed to verify username availability", ex);
            throw new BadRequestException("Could not verify username availability.");
        }
    }

    @Override
    public void bootstrapProfile(UUID userId, String email, String username, String displayName) {
        try {
            restClient.post()
                    .uri(INTERNAL_PROFILES_PATH)
                    .header(INTERNAL_SECRET_HEADER, internalApiSecret)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new BootstrapProfileRequest(userId, email, username, displayName))
                    .retrieve()
                    .toBodilessEntity();
            log.info("Bootstrapped profile for account {}", userId);
        } catch (RestClientResponseException ex) {
            if (ex.getStatusCode().value() == 409) {
                throw new ConflictException("That username is already taken.");
            }
            log.error("Failed to bootstrap profile for account {} — registration succeeded but GET /profile "
                    + "may return 404 until a profile is created manually", userId, ex);
        } catch (RestClientException ex) {
            log.error("Failed to bootstrap profile for account {} — registration succeeded but GET /profile "
                    + "may return 404 until a profile is created manually", userId, ex);
        }
    }

    private RuntimeException mapUsernameCheckFailure(RestClientResponseException ex) {
        return switch (ex.getStatusCode().value()) {
            case 409 -> new ConflictException("That username is already taken.");
            case 400 -> new BadRequestException("username must be 3-20 characters and contain only letters, numbers and underscores.");
            default -> {
                log.error("Unexpected response checking username availability: HTTP {}", ex.getStatusCode().value(), ex);
                yield new BadRequestException("Could not verify username availability.");
            }
        };
    }

    record BootstrapProfileRequest(UUID userId, String email, String username, String displayName) {
    }
}
