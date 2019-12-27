package org.linuxprobe.shiro.security.filter;

import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.servlet.AdviceFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Setter
@Getter
public class LogoutFilter extends AdviceFilter {
    public static final String name = "logout";
    private String loginUrl = "/";

    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        if (this.onLogoutBefore(request, response)) {
            SecurityUtils.getSubject().logout();
            this.onLogoutAfter(request, response);
        }
        return false;
    }

    public boolean onLogoutBefore(ServletRequest request, ServletResponse response) throws IOException {
        return true;
    }

    public void onLogoutAfter(ServletRequest request, ServletResponse response) throws IOException {
        ((HttpServletResponse) response).sendRedirect(this.loginUrl);
    }
}
