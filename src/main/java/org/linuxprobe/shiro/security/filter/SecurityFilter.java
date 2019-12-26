package org.linuxprobe.shiro.security.filter;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Assert;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.linuxprobe.shiro.security.authc.SecurityToken;
import org.linuxprobe.shiro.security.client.Client;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.session.SessionKeyStore;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Getter
@Setter
@NoArgsConstructor
public class SecurityFilter extends AdviceFilter {
    public static final String name = "security";
    private List<Client<?>> clients;
    private boolean lazy;
    private SessionKeyStore sessionKeyStore;

    public SecurityFilter(List<Client<?>> clients, SessionKeyStore sessionKeyStore) {
        this.clients = clients;
        this.sessionKeyStore = sessionKeyStore;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        Subject subject = SecurityUtils.getSubject();
        // 如果交互对象已经认证, 并且开启了惰性验证,则执行其它拦截器链路
        if (subject.isAuthenticated() && this.lazy) {
            return true;
        } else {
            Assert.notNull(this.clients, "clients can not be null");
            SubjectProfile subjectProfile = null;
            Client currnetClient = null;
            for (Client client : this.clients) {
                client.init();
                subjectProfile = client.getSubjectProfile(request);
                currnetClient = client;
                if (subjectProfile != null) {
                    break;
                }
            }
            if (subjectProfile != null) {
                subjectProfile.setClientName(currnetClient.getName());
                try {
                    Session session = subject.getSession();
                    if (this.sessionKeyStore != null) {
                        this.sessionKeyStore.addMap(currnetClient.getSessionIdKey(request), session.getId().toString(), session.getTimeout(), TimeUnit.MILLISECONDS);
                    }
                } catch (Exception ignored) {
                }
                if (!currnetClient.afterHandle(subjectProfile, request, response)) {
                    return false;
                } else {
                    SecurityToken<?> token = new SecurityToken<>(subjectProfile);
                    // 如果交互对象没有登陆, 执行登陆
                    if (!subject.isAuthenticated()) {
                        subject.login(token);
                    }
                    return true;
                }
            } else {
                this.onUnauthorized(request, response);
                return false;
            }
        }
    }

    /**
     * 当认证失败时
     */
    public void onUnauthorized(ServletRequest request, ServletResponse response) {
        throw new SecurityException("Unauthorized");
    }
}
