package org.linuxprobe.shiro.security.credentials.extractor.impl;


import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.CredentialsExtractor;

import javax.servlet.ServletRequest;

public class HeaderParamCookieCredentialsExtractor implements CredentialsExtractor<Credentials> {
    private HeaderCredentialsExtractor headerCredentialsExtractor;
    private ParamCredentialsExtractor paramCredentialsExtractor;
    private CookieCredentialsExtractor cookieCredentialsExtractor;

    public HeaderParamCookieCredentialsExtractor(String headerName, String paramName, String cookieName) {
        Assert.isTrue(!(headerName == null && paramName == null && cookieName == null), "headerName, paramName, cookieName can't all be null");
        if (headerName != null) {
            this.headerCredentialsExtractor = new HeaderCredentialsExtractor(headerName);
        }
        if (paramName != null) {
            this.paramCredentialsExtractor = new ParamCredentialsExtractor(paramName);
        }
        if (cookieName != null) {
            this.cookieCredentialsExtractor = new CookieCredentialsExtractor(cookieName);
        }
    }

    @Override
    public Credentials extract(ServletRequest request) {
        Credentials result = null;
        if (this.headerCredentialsExtractor != null) {
            result = this.headerCredentialsExtractor.extract(request);
        }
        if (result == null && this.paramCredentialsExtractor != null) {
            result = this.paramCredentialsExtractor.extract(request);
        }
        if (result == null && this.cookieCredentialsExtractor != null) {
            result = this.cookieCredentialsExtractor.extract(request);
        }
        return result;
    }
}
