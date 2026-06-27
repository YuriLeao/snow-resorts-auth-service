package com.snowresorts.auth.infrastructure.user;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.snowresorts.auth.application.AuthTokenProperties;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
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

        client.bootstrapProfile(USER_ID, "newrider@snow-resorts.com");

        verify(requestBodySpec).body(eq(new RestProfileBootstrapClient.BootstrapProfileRequest(
                USER_ID, "newrider@snow-resorts.com")));
    }
}
