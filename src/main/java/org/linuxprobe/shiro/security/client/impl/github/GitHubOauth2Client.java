package org.linuxprobe.shiro.security.client.impl.github;

import com.fasterxml.jackson.core.type.TypeReference;
import org.linuxprobe.luava.json.JacksonUtils;
import org.linuxprobe.shiro.security.client.impl.Oauth2Client;
import org.linuxprobe.shiro.security.profile.Oauth2SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.impl.Oauth2ProfileCreator;

import java.util.Map;

public class GitHubOauth2Client extends Oauth2Client {
    public GitHubOauth2Client() {
        super(GitHubApi.instance(), null, new ProfileExtracter());
        this.setProfileUrl("https://api.github.com/user");
        this.setScope("user");
    }

    private static class ProfileExtracter implements Oauth2ProfileCreator.Oauth2SubjectProfileExtracter {
        @Override
        public Oauth2SubjectProfile extractUserProfile(String body) {
            Map<String, Object> map = JacksonUtils.conversion(body, new TypeReference<Map<String, Object>>() {
            });
            Oauth2SubjectProfile profile = new Oauth2SubjectProfile();
            profile.setId(map.get("id").toString());
            profile.getAttributes().putAll(map);
            return profile;
        }
    }
}
