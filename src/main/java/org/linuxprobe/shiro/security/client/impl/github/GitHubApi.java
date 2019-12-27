package org.linuxprobe.shiro.security.client.impl.github;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.extractors.OAuth2AccessTokenExtractor;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth2.clientauthentication.ClientAuthentication;
import com.github.scribejava.core.oauth2.clientauthentication.RequestBodyAuthenticationScheme;

public class GitHubApi extends DefaultApi20 {
    public static GitHubApi instance() {
        return GitHubApi.InstanceHolder.INSTANCE;
    }

    @Override
    public Verb getAccessTokenVerb() {
        return Verb.GET;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return "https://github.com/login/oauth/access_token";
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return "https://github.com/login/oauth/authorize";
    }

    @Override
    public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
        return OAuth2AccessTokenExtractor.instance();
    }

    @Override
    public ClientAuthentication getClientAuthentication() {
        return RequestBodyAuthenticationScheme.instance();
    }

    private static class InstanceHolder {
        private static final GitHubApi INSTANCE = new GitHubApi();

        private InstanceHolder() {
        }
    }
}
