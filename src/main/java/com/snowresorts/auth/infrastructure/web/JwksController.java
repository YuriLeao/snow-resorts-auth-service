package com.snowresorts.auth.infrastructure.web;

import com.nimbusds.jose.jwk.JWKSet;
import com.snowresorts.auth.infrastructure.jwt.RsaKeyProvider;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the JSON Web Key Set so resource servers (every other service) can validate
 * access tokens. Only public key material is exposed.
 */
@RestController
public class JwksController {

    private final RsaKeyProvider keyProvider;

    public JwksController(RsaKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
    public Map<String, Object> jwks() {
        return new JWKSet(keyProvider.publicKey()).toJSONObject();
    }
}
