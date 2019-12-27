package org.linuxprobe.shiro.security.profile;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Oauth2SubjectProfile extends SubjectProfile {
    private static final long serialVersionUID = -3744499248993269044L;
    /**
     * 是否需要认证
     */
    private boolean needAuth = false;
}
