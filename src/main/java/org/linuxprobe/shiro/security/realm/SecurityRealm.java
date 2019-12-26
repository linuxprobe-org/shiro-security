package org.linuxprobe.shiro.security.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.linuxprobe.shiro.security.authc.SecurityToken;
import org.linuxprobe.shiro.security.profile.SubjectProfile;

public class SecurityRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return new SimpleAuthorizationInfo();
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        SecurityToken securityToken = (SecurityToken) token;
        return new SimpleAuthenticationInfo(securityToken.getPrincipal(), securityToken.getCredentials(),
                this.getName());
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return SecurityToken.class.isAssignableFrom(token.getClass());
    }

    @Override
    public String getAuthorizationCacheName() {
        return "securityRealm";
    }

    /**
     * 获取授权缓存信息的key
     */
    @Override
    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        SubjectProfile subjectProfile = (SubjectProfile) principals.getPrimaryPrincipal();
        return subjectProfile.getClientName() + ":" + subjectProfile.getId();
    }
}
