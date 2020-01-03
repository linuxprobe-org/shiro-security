package org.linuxprobe.shiro.security.credentials.extractor.impl;

import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.CredentialsExtractor;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class CookieCredentialsExtractor implements CredentialsExtractor<Credentials> {
    private String cookieName;

    public CookieCredentialsExtractor(String cookieName) {
        Assert.notNull(cookieName, "cookieName can not be null");
        this.cookieName = cookieName;
    }

    @Override
    public Credentials extract(ServletRequest request) {
        Cookie[] cookies = ((HttpServletRequest) request).getCookies();
        String paramValue = null;
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(this.cookieName)) {
                    paramValue = cookie.getValue();
                }
            }
        }
        if (paramValue != null && !paramValue.isEmpty()) {
            Credentials credentials = new Credentials();
            credentials.setCredentialsValue(paramValue);
            return credentials;
        }
        return null;
    }
}
