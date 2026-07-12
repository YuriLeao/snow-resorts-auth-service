package com.snowresorts.auth.infrastructure.user;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.snowresorts.auth.application.AuthTokenProperties;
import com.snowresorts.security.error.ConflictException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@ExtendWith(MockitoExtension.class)
class RestProfileBootstrapClientTest {

    private static final UUID USER_ID = UUID.fromString("33333333-3333-3333-3333-333333333333");

    @Mock
    private RestClient restClient;
    @Mock
    private RestClient.RequestBodyUriSpec requestBodyUriSpec;
    @Mock
    private RestClient.RequestBodySpec requestBodySpec;
    @Mock
    private RestClient.RequestHeadersUriSpec requestHeadersUriSpec;
    @Mock
    private RestClient.RequestHeadersSpec requestHeadersSpec;
    @Mock
    private RestClient.ResponseSpec responseSpec;

    private RestProfileBootstrapClient client;

    @BeforeEach
    void setUp() {
        AuthTokenProperties properties = new AuthTokenProperties(
                "https://auth.test",
                Duration.ofMinutes(15),
                Duration.ofDays(30),
                "k1",
                Duration.ofHours(1),
                null,
                "http://localhost:8082",
                "test-secret");
        client = new RestProfileBootstrapClient(restClient, properties);
    }

    @Test
    @DisplayName("ensureUsernameAvailable GETs the internal availability endpoint with shared secret")
    void ensureUsernameAvailable_invokesInternalEndpoint() {
        when(restClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri("/snow-resort-service/v1/users/internal/usernames/{username}/available", "newrider"))
                .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header("X-Internal-Secret", "test-secret")).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        client.ensureUsernameAvailable("newrider");

        verify(requestHeadersSpec).header("X-Internal-Secret", "test-secret");
    }

    @Test
    @DisplayName("ensureUsernameAvailable maps HTTP 409 to ConflictException")
    void ensureUsernameAvailable_whenTaken_throwsConflict() {
        when(restClient.get()).thenReturn(requestHeadersUriSpec);
        when(requestHeadersUriSpec.uri("/snow-resort-service/v1/users/internal/usernames/{username}/available", "taken"))
                .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header("X-Internal-Secret", "test-secret")).thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenThrow(
                HttpClientErrorException.create(
                        HttpStatus.CONFLICT,
                        "Conflict",
                        null,
                        null,
                        StandardCharsets.UTF_8));

        assertThatThrownBy(() -> client.ensureUsernameAvailable("taken"))
                .isInstanceOf(ConflictException.class);
    }

    @Test
    @DisplayName("bootstrapProfile POSTs to user-service internal endpoint with shared secret")
    void bootstrapProfile_invokesInternalEndpoint() {
        when(restClient.post()).thenReturn(requestBodyUriSpec);
        when(requestBodyUriSpec.uri("/snow-resort-service/v1/users/internal/profiles")).thenReturn(requestBodySpec);
        when(requestBodySpec.header("X-Internal-Secret", "test-secret")).thenReturn(requestBodySpec);
        when(requestBodySpec.contentType(MediaType.APPLICATION_JSON)).thenReturn(requestBodySpec);
        when(requestBodySpec.body(any(RestProfileBootstrapClient.BootstrapProfileRequest.class)))
                .thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        client.bootstrapProfile(USER_ID, "newrider@snow-resorts.com", "newrider", "New Rider");

        verify(requestBodySpec).body(eq(new RestProfileBootstrapClient.BootstrapProfileRequest(
                USER_ID, "newrider@snow-resorts.com", "newrider", "New Rider")));
    }
}
