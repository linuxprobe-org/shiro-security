package org.linuxprobe.shiro.security.client.impl;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.impl.ParameterCredentialsExtractor;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.ProfileCreator;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

@Getter
@Setter
@NoArgsConstructor
public class CookieClient<P extends SubjectProfile> extends BaseClient<P, Credentials> {
    private String cookieName;

    public CookieClient(String name, String cookieName, ProfileCreator<P, Credentials> profileCreator) {
        this.setName(name);
        this.cookieName = cookieName;
        this.setCredentialsExtractor(new ParameterCredentialsExtractor(this.cookieName));
        this.setProfileCreator(profileCreator);
    }


    @Override
    public String getSessionIdKey(ServletRequest request) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        return httpServletRequest.getHeader(this.cookieName);
    }

    @Override
    public boolean isSupport(ServletRequest request) {
        boolean clientNameInUrl = super.isSupport(request);
        if (clientNameInUrl) {
            return true;
        } else {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request;
            String headerValue = httpServletRequest.getHeader(this.cookieName);
            return headerValue != null && !headerValue.isEmpty();
        }
    }

    @Override
    public void init() {
        super.init();
        Assert.notNull(this.getName(), "name can not be null");
        Assert.notNull(this.cookieName, "cookieName can not be null");
    }
}
