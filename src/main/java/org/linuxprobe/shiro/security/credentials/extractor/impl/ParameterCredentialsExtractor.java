package org.linuxprobe.shiro.security.credentials.extractor.impl;

import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.CredentialsExtractor;

import javax.servlet.ServletRequest;

public class ParameterCredentialsExtractor implements CredentialsExtractor<Credentials> {
    private String paramaName;

    public ParameterCredentialsExtractor(String paramaName) {
        Assert.notNull(paramaName, "paramaName can not be null");
        this.paramaName = paramaName;
    }

    @Override
    public Credentials extract(ServletRequest request) {
        String paramValue = request.getParameter(this.paramaName);
        if (paramValue != null && !paramValue.isEmpty()) {
            Credentials credentials = new Credentials();
            credentials.setCredentialsValue(paramValue);
            return credentials;
        }
        return null;
    }
}
