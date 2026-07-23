package com.snowresorts.auth.infrastructure.user;

import com.snowresorts.auth.application.AuthTokenProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class UserServiceClientConfig {

    @Bean
    RestClient userServiceRestClient(RestClient.Builder restClientBuilder, AuthTokenProperties properties) {
        return restClientBuilder
                .baseUrl(properties.userServiceUrl())
                .build();
    }
}
