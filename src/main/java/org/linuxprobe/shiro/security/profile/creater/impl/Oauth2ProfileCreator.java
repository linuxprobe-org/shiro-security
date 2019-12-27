package org.linuxprobe.shiro.security.profile.creater.impl;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.profile.Oauth2SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.ProfileCreator;
import org.linuxprobe.shiro.utils.SubjectUtils;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

@Getter
@Setter
public class Oauth2ProfileCreator implements ProfileCreator<Oauth2SubjectProfile, Credentials> {
    private OAuth20Service oAuth20Service;
    private String profileUrl;
    private Verb profileVerb = Verb.GET;
    private Oauth2SubjectProfileExtracter profileExtracter;

    public Oauth2ProfileCreator(OAuth20Service oAuth20Service, String profileUrl, Oauth2SubjectProfileExtracter profileExtracter) {
        this.oAuth20Service = oAuth20Service;
        this.profileUrl = profileUrl;
        this.profileExtracter = profileExtracter;
    }

    /**
     * 使用凭证获取access token
     */
    public OAuth2AccessToken requestAccessToken(String code) {
        Assert.notNull(this.oAuth20Service, "oAuth20Service can not be null");
        OAuth2AccessToken accessToken = null;
        try {
            accessToken = this.oAuth20Service.getAccessToken(code);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return accessToken;
    }

    /**
     * 给请求添加认证
     */
    public void signRequest(OAuthRequest request, OAuth2AccessToken accessToken) {
        request.addQuerystringParameter("access_token", accessToken.getAccessToken());
    }

    /**
     * 使用access token请求用户信息
     */
    public Oauth2SubjectProfile requestUserProfile(OAuth2AccessToken accessToken) {
        Assert.notNull(this.oAuth20Service, "oAuth20Service can not be null");
        Assert.notNull(this.profileVerb, "profileVerb can not be null");
        Assert.notNull(this.profileUrl, "profileUrl can not be null");
        Assert.notNull(this.profileExtracter, "profileExtracter can not be null");
        final OAuthRequest request = new OAuthRequest(this.profileVerb, this.profileUrl);
        this.signRequest(request, accessToken);
        Response response = null;
        try {
            response = this.oAuth20Service.execute(request);
        } catch (final IOException | InterruptedException | ExecutionException e) {
            throw new RuntimeException(e);
        }
        if (response.getCode() != 200) {
            throw new SecurityException("request user profile fail");
        }
        String body = null;
        try {
            body = response.getBody();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return this.profileExtracter.extractUserProfile(body);
    }


    @Override
    public Oauth2SubjectProfile create(Credentials credentials) {
        Assert.notNull(this.oAuth20Service, "oAuth20Service can not be null");
        Oauth2SubjectProfile profile = null;
        Subject subject = SecurityUtils.getSubject();
        // 会话对象未认证
        if (!subject.isAuthenticated()) {
            // 如果有回调凭证码
            if (credentials != null && credentials.getCredentialsValue() != null) {
                OAuth2AccessToken accessToken = null;
                try {
                    accessToken = this.requestAccessToken(credentials.getCredentialsValue());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                profile = this.requestUserProfile(accessToken);
            }
            // 没有回调凭证码
            else {
                profile = new Oauth2SubjectProfile();
                profile.setNeedAuth(true);
            }
        } else {
            profile = (Oauth2SubjectProfile) SubjectUtils.getSessionCommonProfile();
        }
        return profile;
    }

    /**
     * 用户信息提取
     */
    public static interface Oauth2SubjectProfileExtracter {
        Oauth2SubjectProfile extractUserProfile(String body);
    }
}
