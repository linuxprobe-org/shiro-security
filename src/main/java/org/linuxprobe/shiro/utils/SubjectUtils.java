package org.linuxprobe.shiro.utils;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.linuxprobe.shiro.security.profile.SubjectProfile;

public class SubjectUtils {
    /**
     * 获取当前会话对象的配置
     */
    public static SubjectProfile getSessionCommonProfile() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            SubjectProfile pac4jPrincipal = (SubjectProfile) subject.getPrincipal();
            return null;
        }
        return null;
    }

    /**
     * 获取当前会话对象
     */
    public static Subject getSessionSubject() {
        return SecurityUtils.getSubject();
    }
}
