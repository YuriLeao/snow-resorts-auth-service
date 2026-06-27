package com.snowresorts.auth.infrastructure.user;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.auth.domain.port.ProfileBootstrap;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

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
    public void bootstrapProfile(UUID userId, String email) {
        try {
            restClient.post()
                    .uri(INTERNAL_PROFILES_PATH)
                    .header(INTERNAL_SECRET_HEADER, internalApiSecret)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new BootstrapProfileRequest(userId, email))
                    .retrieve()
                    .toBodilessEntity();
            log.info("Bootstrapped profile for account {}", userId);
        } catch (RestClientException ex) {
            log.error("Failed to bootstrap profile for account {} — registration succeeded but GET /profile "
                    + "may return 404 until a profile is created manually", userId, ex);
        }
    }

    record BootstrapProfileRequest(UUID userId, String email) {
    }
}
