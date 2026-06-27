package com.snowresorts.auth.domain.port;

import com.snowresorts.auth.domain.model.IssuedAccessToken;
import com.snowresorts.auth.domain.model.UserAccount;

/** Outbound port that signs a short-lived access token for an authenticated account. */
public interface AccessTokenIssuer {

    IssuedAccessToken issue(UserAccount account);
}
