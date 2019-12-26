package org.linuxprobe.shiro.security.client;

import org.linuxprobe.shiro.security.profile.SubjectProfile;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public interface Client<P extends SubjectProfile> {
    /**
     * client name
     */
    String getName();

    /**
     * 获取当前会话对象的配置
     */
    P getSubjectProfile(ServletRequest request);

    /**
     * 后续处理, 如果返回false,将不执行后续的操作
     */
    boolean afterHandle(P profile, ServletRequest request, ServletResponse response);

    /**
     * 获取sessionId映射key
     *
     * @return null或者key
     */
    String getSessionIdKey(ServletRequest request);

    /**
     * 惰性校验,如果开启,shiro subject已登陆情况下将不再进行校验
     */
    boolean lazyVerification();

    /**
     * 判断当前请求是否支持该client
     */
    boolean isSupport(ServletRequest request);

    /**
     * 初始化
     */
    void init();
}
