package org.linuxprobe.shiro.security.filter.advice;

import org.linuxprobe.shiro.security.profile.SubjectProfile;

/**
 * 登陆前后处理
 */
public interface SigninAdvice {
    default void signinBefore(SubjectProfile profile) {
    }

    default void signinAfter(SubjectProfile profile) {
    }
}
