package org.linuxprobe.shiro.security.credentials.extractor.impl;

import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.CredentialsExtractor;

import javax.servlet.ServletRequest;

public class ParamCredentialsExtractor implements CredentialsExtractor<Credentials> {
    private String paramName;

    public ParamCredentialsExtractor(String paramName) {
        Assert.notNull(paramName, "paramName can not be null");
        this.paramName = paramName;
    }

    @Override
    public Credentials extract(ServletRequest request) {
        String paramValue = request.getParameter(this.paramName);
        if (paramValue != null && !paramValue.isEmpty()) {
            Credentials credentials = new Credentials();
            credentials.setCredentialsValue(paramValue);
            return credentials;
        }
        return null;
    }
}
