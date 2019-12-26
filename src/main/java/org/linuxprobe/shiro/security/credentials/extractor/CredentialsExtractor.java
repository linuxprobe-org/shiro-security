package org.linuxprobe.shiro.security.credentials.extractor;

import org.linuxprobe.shiro.security.credentials.Credentials;

import javax.servlet.ServletRequest;

public interface CredentialsExtractor<C extends Credentials> {
    C extract(ServletRequest request);
}
