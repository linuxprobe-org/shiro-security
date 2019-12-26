package org.linuxprobe.shiro.security.filter;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.web.servlet.AdviceFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class RedirectionFilter extends AdviceFilter {
    public static final String name = "redirection";

    private Map<String, String> redirections;

    public RedirectionFilter(Map<String, String> redirections) {
        this.redirections = redirections;
    }

    /**
     * 如果返回 true 则继续拦截器链；否则中断后续的拦截器链的执行直接返回
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        if (this.redirections != null && !this.redirections.isEmpty()) {
            String requestUri = httpServletRequest.getRequestURI();
            if (this.redirections.containsKey(requestUri)) {
                String redirectUrl = this.redirections.get(requestUri);
                String queryString = httpServletRequest.getQueryString();
                if (queryString != null) {
                    if (redirectUrl.contains("?")) {
                        redirectUrl += "&" + queryString;
                    } else {
                        redirectUrl += "?" + queryString;
                    }
                }
                if (redirectUrl.toLowerCase().startsWith("http")) {
                    httpServletResponse.sendRedirect(redirectUrl);
                } else {
                    httpServletResponse.setStatus(302);
                    httpServletResponse.setHeader("Location", redirectUrl);
                }
                return false;
            }
        }
        return true;
    }
}
