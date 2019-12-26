package org.linuxprobe.shiro.security.authc;

import org.apache.shiro.authc.RememberMeAuthenticationToken;
import org.linuxprobe.shiro.security.profile.SubjectProfile;

public class SecurityToken<P extends SubjectProfile> implements RememberMeAuthenticationToken {
    private static final long serialVersionUID = 216609319386173039L;
    private P profile;
    private boolean rememberMe;

    public SecurityToken(P profile, boolean rememberMe) {
        this.profile = profile;
        this.rememberMe = rememberMe;
    }

    public SecurityToken(P profile) {
        this(profile, true);
    }

    @Override
    public boolean isRememberMe() {
        return this.rememberMe;
    }

    @Override
    public Object getPrincipal() {
        return this.profile;
    }

    @Override
    public Object getCredentials() {
        return this.profile.hashCode();
    }
}
