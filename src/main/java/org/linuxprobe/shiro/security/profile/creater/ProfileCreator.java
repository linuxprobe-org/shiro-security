package org.linuxprobe.shiro.security.profile.creater;

import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.profile.SubjectProfile;

public interface ProfileCreator<P extends SubjectProfile, C extends Credentials> {
    P create(C credentials);
}
