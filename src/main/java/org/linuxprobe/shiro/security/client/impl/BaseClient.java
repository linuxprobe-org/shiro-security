package org.linuxprobe.shiro.security.client.impl;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.client.Client;
import org.linuxprobe.shiro.security.constant.SecurityConstant;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.CredentialsExtractor;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.ProfileCreator;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

@Setter
@Getter
@NoArgsConstructor
public abstract class BaseClient<P extends SubjectProfile, C extends Credentials> implements Client<P> {
    private CredentialsExtractor<C> credentialsExtractor;
    private ProfileCreator<P, C> profileCreator;
    private boolean lazyVerification = false;
    private String name;

    public BaseClient(CredentialsExtractor<C> credentialsExtractor, ProfileCreator<P, C> profileCreator) {
        this.credentialsExtractor = credentialsExtractor;
        this.profileCreator = profileCreator;
    }

    @Override
    public P getSubjectProfile(ServletRequest request) {
        C credentials = this.credentialsExtractor.extract(request);
        return this.profileCreator.create(credentials);
    }

    @Override
    public boolean afterHandle(P profile, ServletRequest request, ServletResponse response) {
        return true;
    }

    @Override
    public void init() {
        Assert.notNull(this.credentialsExtractor, "credentialsExtractor can not be null");
        Assert.notNull(this.profileCreator, "profileCreator can not be null");
    }

    @Override
    public boolean isSupport(ServletRequest request) {
        String clientName = request.getParameter(SecurityConstant.clientName);
        return clientName != null && clientName.equals(this.getName());
    }

    @Override
    public String getSessionIdKey(ServletRequest request) {
        return null;
    }

    @Override
    public boolean lazyVerification() {
        return this.lazyVerification;
    }
}
