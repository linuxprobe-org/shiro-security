package org.linuxprobe.shiro.security.client.impl;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.oauth.OAuth20Service;
import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.impl.ParameterCredentialsExtractor;
import org.linuxprobe.shiro.security.profile.Oauth2SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.impl.Oauth2ProfileCreator;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Getter
@Setter
public class Oauth2Client extends BaseClient<Oauth2SubjectProfile, Credentials> {
    /**
     * oauth api定义
     */
    private DefaultApi20 api;
    /**
     * 回调地址
     */
    private String callBack;
    /**
     * key
     */
    private String clientKey;
    /**
     * secret
     */
    private String clientSecret;
    /**
     * 返回类型
     */
    private String responseType = "code";
    /**
     * 域
     */
    private String scope;
    /**
     * 自定义标识
     */
    private String state;
    /**
     * oauth2 client 用户配置创建对象
     */
    private Oauth2ProfileCreator oauth2ProfileCreator;
    /**
     * 用户信息提取地址
     */
    private String profileUrl;
    /**
     * 用户信息提取器
     */
    private Oauth2ProfileCreator.Oauth2SubjectProfileExtracter profileExtracter;

    public Oauth2Client(DefaultApi20 api, Oauth2ProfileCreator oauth2ProfileCreator, Oauth2ProfileCreator.Oauth2SubjectProfileExtracter profileExtracter) {
        this.setCredentialsExtractor(new ParameterCredentialsExtractor("code"));
        this.api = api;
        this.oauth2ProfileCreator = oauth2ProfileCreator;
        this.profileExtracter = profileExtracter;
        this.setLazyVerification(true);
    }

    @Override
    public boolean afterHandle(Oauth2SubjectProfile profile, ServletRequest request, ServletResponse response) {
        if (profile.isNeedAuth()) {
            String loginUrl = this.api.getAuthorizationUrl(this.responseType, this.clientKey, this.callBack, this.scope, this.state, null);
            try {
                ((HttpServletResponse) response).sendRedirect(loginUrl);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return false;
        } else {
            return true;
        }
    }

    @Override
    public void init() {
        Assert.notNull(this.api, "api can not be null");
        Assert.notNull(this.callBack, "callBack can not be null");
        Assert.notNull(this.clientKey, "clientKey can not be null");
        Assert.notNull(this.clientSecret, "clientSecret can not be null");
        Assert.notNull(this.profileUrl, "profileUrl can not be null");
        Assert.notNull(this.profileExtracter, "profileExtracter can not be null");
        if (this.getProfileCreator() == null) {
            OAuth20Service oAuth20Service = this.api.createService(this.clientKey, this.clientSecret, this.callBack, this.scope, this.responseType, null, null, null, null);
            this.setProfileCreator(new Oauth2ProfileCreator(oAuth20Service, this.profileUrl, this.profileExtracter));
        }
        super.init();
    }

    @Override
    public boolean isSupport(ServletRequest request) {
        return this.getName().equals(request.getParameter("state")) || super.isSupport(request);
    }
}
