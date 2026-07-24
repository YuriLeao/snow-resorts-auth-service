package com.snowresorts.auth;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import com.snowresorts.auth.application.RefreshTokenCodec;
import com.snowresorts.auth.domain.port.ProfileBootstrap;
import com.snowresorts.auth.infrastructure.persistence.PasswordResetTokenEntity;
import com.snowresorts.auth.infrastructure.persistence.PasswordResetTokenJpaRepository;
import com.snowresorts.auth.infrastructure.persistence.UserAccountEntity;
import com.snowresorts.auth.infrastructure.persistence.UserAccountJpaRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class AuthControllerIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("imresamu/postgis:16-3.4").asCompatibleSubstituteFor("postgres"))
            .withDatabaseName("snow_resorts")
            .withUsername("snow")
            .withPassword("snow");

    @DynamicPropertySource
    static void datasourceProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserAccountJpaRepository userAccounts;
    @Autowired
    private PasswordResetTokenJpaRepository passwordResetTokens;
    @Autowired
    private JsonMapper objectMapper;

    /** User-service is not running in this IT; registration only needs auth DB + tokens. */
    @MockitoBean
    private ProfileBootstrap profileBootstrap;

    private UUID seededUserId;

    @BeforeEach
    void seedUser() {
        passwordResetTokens.deleteAll();
        userAccounts.deleteAll();
        String hash = new BCryptPasswordEncoder().encode("Password123!");
        seededUserId = UUID.randomUUID();
        userAccounts.save(new UserAccountEntity(
                seededUserId, "rider@snow-resorts.com", hash, true, Instant.now()));
    }

    @Test
    @DisplayName("POST /login then /refresh issues and rotates tokens end-to-end")
    void loginThenRefresh_endToEnd() throws Exception {
        // Act + Assert: login
        MvcResult loginResult = mockMvc.perform(post("/snow-resort-service/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"rider@snow-resorts.com","password":"Password123!"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        JsonNode tokens = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        String refreshToken = tokens.get("refreshToken").asText();

        // Act + Assert: refresh rotates the token
        mockMvc.perform(post("/snow-resort-service/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                java.util.Map.of("refreshToken", refreshToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()));
    }

    @Test
    @DisplayName("POST /login with a wrong password returns RFC 7807 401")
    void login_wrongPassword_returns401Problem() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"rider@snow-resorts.com","password":"wrong"}"""))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Unauthorized"));
    }

    @Test
    @DisplayName("POST /login with an invalid email body returns RFC 7807 400 with field errors")
    void login_invalidEmail_returns400Validation() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"not-an-email","password":""}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Validation Failed"))
                .andExpect(jsonPath("$.errors", notNullValue()));
    }

    @Test
    @DisplayName("POST /register with a new email creates the account, returns 201 and issues tokens")
    void register_newEmail_returns201WithTokens() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"NewRider@snow-resorts.com","password":"Password123!","username":"newrider","displayName":"New Rider"}"""))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));

        // The new account can authenticate immediately with the chosen password.
        mockMvc.perform(post("/snow-resort-service/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"newrider@snow-resorts.com","password":"Password123!"}"""))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /register with an already-registered email returns RFC 7807 409")
    void register_duplicateEmail_returns409() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"Rider@snow-resorts.com","password":"Password123!","username":"riderdup","displayName":"Rider"}"""))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.title").value("Conflict"));
    }

    @Test
    @DisplayName("POST /register with a weak password and blank email returns RFC 7807 400 with field errors")
    void register_invalidBody_returns400Validation() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"","password":"short"}"""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Validation Failed"))
                .andExpect(jsonPath("$.errors", notNullValue()));
    }

    @Test
    @DisplayName("POST /forgot-password returns 204 for a known account without leaking existence")
    void forgotPassword_knownEmail_returns204() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"rider@snow-resorts.com"}"""))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("POST /forgot-password returns 204 for an unknown account (no account-enumeration)")
    void forgotPassword_unknownEmail_returns204() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"ghost@snow-resorts.com"}"""))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("POST /reset-password with a valid token sets the new password and consumes the token")
    void resetPassword_validToken_returns204AndUpdatesPassword() throws Exception {
        // Arrange: persist a reset token by hash, mirroring how the service stores it.
        String rawToken = RefreshTokenCodec.newRawToken();
        passwordResetTokens.save(new PasswordResetTokenEntity(
                UUID.randomUUID(), seededUserId, RefreshTokenCodec.hash(rawToken),
                Instant.now().plus(1, ChronoUnit.HOURS), false, Instant.now()));

        // Act: reset
        mockMvc.perform(post("/snow-resort-service/v1/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "token", rawToken, "newPassword", "BrandNew123!"))))
                .andExpect(status().isNoContent());

        // Assert: the new password works and the token is single-use (second attempt rejected).
        mockMvc.perform(post("/snow-resort-service/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"rider@snow-resorts.com","password":"BrandNew123!"}"""))
                .andExpect(status().isOk());

        mockMvc.perform(post("/snow-resort-service/v1/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "token", rawToken, "newPassword", "Another123!"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /reset-password with an unknown token returns RFC 7807 400")
    void resetPassword_invalidToken_returns400() throws Exception {
        mockMvc.perform(post("/snow-resort-service/v1/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "token", "does-not-exist", "newPassword", "BrandNew123!"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").value("Bad Request"));
    }
}
