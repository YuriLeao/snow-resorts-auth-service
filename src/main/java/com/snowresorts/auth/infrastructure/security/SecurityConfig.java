package com.snowresorts.auth.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Auth-service security: registration, login, refresh, password-recovery, logout and JWKS are
 * public. Logout is {@code permitAll} because the refresh token in the body is the credential.
 * Declaring this {@code SecurityFilterChain} disables the shared resource-server default from
 * {@code security-lib}.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/snow-resort-service/v1/auth/register",
                                "/snow-resort-service/v1/auth/login",
                                "/snow-resort-service/v1/auth/refresh",
                                "/snow-resort-service/v1/auth/logout",
                                "/snow-resort-service/v1/auth/forgot-password",
                                "/snow-resort-service/v1/auth/reset-password",
                                "/.well-known/jwks.json",
                                "/actuator/health/**",
                                "/actuator/health",
                                "/actuator/info",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html").permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
