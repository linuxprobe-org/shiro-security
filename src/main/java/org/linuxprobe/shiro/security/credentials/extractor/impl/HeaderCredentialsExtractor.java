package org.linuxprobe.shiro.security.credentials.extractor.impl;

import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.CredentialsExtractor;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

@Getter
@Setter
public class HeaderCredentialsExtractor implements CredentialsExtractor<Credentials> {
    private String headerName;

    public HeaderCredentialsExtractor(String headerName) {
        Assert.notNull(headerName, "headerName can not be null");
        this.headerName = headerName;
    }

    @Override
    public Credentials extract(ServletRequest request) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String header = httpServletRequest.getHeader(this.headerName);
        if (header != null && !header.isEmpty()) {
            Credentials credentials = new Credentials();
            credentials.setCredentialsValue(header);
            return credentials;
        }
        return null;
    }
}
