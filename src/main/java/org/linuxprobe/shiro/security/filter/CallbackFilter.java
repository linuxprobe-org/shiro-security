package org.linuxprobe.shiro.security.filter;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.util.Assert;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.linuxprobe.shiro.security.authc.SecurityToken;
import org.linuxprobe.shiro.security.client.Client;
import org.linuxprobe.shiro.security.client.finder.ClientFinder;
import org.linuxprobe.shiro.security.client.finder.DefaultClientFinder;
import org.linuxprobe.shiro.security.filter.advice.SigninAdvice;
import org.linuxprobe.shiro.security.profile.SubjectProfile;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class CallbackFilter extends AdviceFilter {
    public static final String name = "callback";
    private List<Client<?>> clients;
    private String defaultClient;
    private String homePage = "/";
    private ClientFinder clientFinder = DefaultClientFinder.getInstance();
    private SigninAdvice signinAdvice;

    public CallbackFilter(List<Client<?>> clients) {
        this.clients = clients;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        // 未认证
        boolean unauthorized = true;
        Assert.notNull(this.clients, "clients can not be null");
        Client currentClient = this.clientFinder.find(request, this.defaultClient, this.clients);
        SubjectProfile subjectProfile = null;
        if (currentClient != null) {
            currentClient.init();
            subjectProfile = currentClient.getSubjectProfile(request);
            if (subjectProfile != null) {
                if (!currentClient.afterHandle(subjectProfile, request, response)) {
                    return false;
                }
                subjectProfile.setClientName(currentClient.getName());
                if (this.signinAdvice != null) {
                    this.signinAdvice.signinBefore(subjectProfile);
                }
                SecurityUtils.getSubject().login(new SecurityToken<>(subjectProfile));
                if (this.signinAdvice != null) {
                    this.signinAdvice.signinAfter(subjectProfile);
                }
                unauthorized = false;
            }
        }
        // 如果未认证
        if (unauthorized) {
            this.onUnauthorized(request, response);
        }
        //如果认证成功
        else {
            this.onAuthorized(request, response, subjectProfile);
        }
        return false;
    }

    /**
     * 当认证失败时
     */
    public void onUnauthorized(ServletRequest request, ServletResponse response) {
        throw new SecurityException("Unauthorized");
    }

    /**
     * 当认证成功时
     */
    public void onAuthorized(ServletRequest request, ServletResponse response, SubjectProfile subjectProfile) throws IOException {
        ((HttpServletResponse) response).sendRedirect(this.homePage);
    }
}
