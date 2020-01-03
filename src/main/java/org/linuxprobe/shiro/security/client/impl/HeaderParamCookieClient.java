package org.linuxprobe.shiro.security.client.impl;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.impl.HeaderParamCookieCredentialsExtractor;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.ProfileCreator;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

@Getter
@Setter
@NoArgsConstructor
public class HeaderParamCookieClient<P extends SubjectProfile> extends BaseClient<P, Credentials> {
    private String headerName;
    private String paramName;
    private String cookieName;

    public HeaderParamCookieClient(String name, String headerName, String paramName, String cookieName, ProfileCreator<P, Credentials> profileCreator) {
        this.setName(name);
        this.headerName = headerName;
        this.paramName = paramName;
        this.cookieName = cookieName;
        this.setCredentialsExtractor(new HeaderParamCookieCredentialsExtractor(this.headerName, this.paramName, this.cookieName));
        this.setProfileCreator(profileCreator);
    }


    @Override
    public String getSessionIdKey(ServletRequest request) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        return httpServletRequest.getHeader(this.headerName);
    }

    @Override
    public boolean isSupport(ServletRequest request) {
        boolean clientNameInUrl = super.isSupport(request);
        if (clientNameInUrl) {
            return true;
        } else {
            return this.getCredentialsExtractor().extract(request) != null;
        }
    }

    @Override
    public void init() {
        super.init();
        Assert.notNull(this.getName(), "name can not be null");
        Assert.isTrue(!(this.headerName == null && this.paramName == null && this.cookieName == null), "headerName, paramName, cookieName can't all be null");
    }
}
