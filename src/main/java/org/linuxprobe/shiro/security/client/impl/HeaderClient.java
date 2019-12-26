package org.linuxprobe.shiro.security.client.impl;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.impl.HeaderCredentialsExtractor;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.ProfileCreator;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

@Getter
@Setter
@NoArgsConstructor
public class HeaderClient<P extends SubjectProfile> extends BaseClient<P, Credentials> {
    private String name;
    private String headerName;

    public HeaderClient(String name, String headerName, ProfileCreator<P, Credentials> profileCreator) {
        this.name = name;
        this.headerName = headerName;
        this.setCredentialsExtractor(new HeaderCredentialsExtractor(this.headerName));
        this.setProfileCreator(profileCreator);
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getSessionIdKey(ServletRequest request) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        return httpServletRequest.getHeader(this.headerName);
    }

    @Override
    public void init() {
        super.init();
        Assert.notNull(this.name, "name can not be null");
        Assert.notNull(this.headerName, "headerName can not be null");
    }
}
