package com.cos.security1.oauth.provider;

public interface OAuth2UserInfo {
    String getProvider();

    String getProviderId();

    String getName();

    String getEmail();
}
