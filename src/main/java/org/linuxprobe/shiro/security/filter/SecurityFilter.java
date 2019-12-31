package org.linuxprobe.shiro.security.filter;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Assert;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.linuxprobe.shiro.security.authc.SecurityToken;
import org.linuxprobe.shiro.security.client.Client;
import org.linuxprobe.shiro.security.client.finder.ClientFinder;
import org.linuxprobe.shiro.security.client.finder.DefaultClientFinder;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.session.SessionKeyStore;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Getter
@Setter
@NoArgsConstructor
public class SecurityFilter extends AccessControlFilter {
    public static final String name = "security";
    private List<Client<?>> clients;
    private String defaultClient;
    private SessionKeyStore sessionKeyStore;
    private ClientFinder clientFinder = DefaultClientFinder.getInstance();
    private boolean enableSession = true;

    public SecurityFilter(List<Client<?>> clients, SessionKeyStore sessionKeyStore) {
        this.clients = clients;
        this.sessionKeyStore = sessionKeyStore;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        // 未认证
        boolean unauthorized = true;
        Subject subject = this.getSubject(request, response);
        Assert.notNull(this.clients, "clients can not be null");
        Client currentClient = this.clientFinder.find(request, this.defaultClient, this.clients);
        if (currentClient != null) {
            currentClient.init();
            // 如果shir subject已经登陆并且client开启了惰性认证, 则继续执行其它拦截器
            if (subject.isAuthenticated() && currentClient.lazyVerification()) {
                return true;
            }
            SubjectProfile subjectProfile = currentClient.getSubjectProfile(request);
            if (subjectProfile != null) {
                if (!currentClient.afterHandle(subjectProfile, request, response)) {
                    return false;
                }
                subjectProfile.setClientName(currentClient.getName());
                if (!subject.isAuthenticated()) {
                    SecurityToken<?> token = new SecurityToken<>(subjectProfile);
                    subject.login(token);
                }
                if (this.enableSession) {
                    // 更新key与sessionId的映射
                    try {
                        Session session = subject.getSession();
                        if (this.sessionKeyStore != null) {
                            this.sessionKeyStore.addMap(currentClient.getSessionIdKey(request), session.getId().toString(), session.getTimeout(), TimeUnit.MILLISECONDS);
                        }
                    } catch (Exception ignored) {
                    }
                }
                // 认证成功
                unauthorized = false;
            }
        }
        return !unauthorized;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        throw new SecurityException("Unauthorized");
    }
}
