package org.linuxprobe.shiro.security.client.impl;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.apache.shiro.util.Assert;
import org.linuxprobe.shiro.security.credentials.Credentials;
import org.linuxprobe.shiro.security.credentials.extractor.impl.ParamCredentialsExtractor;
import org.linuxprobe.shiro.security.profile.SubjectProfile;
import org.linuxprobe.shiro.security.profile.creater.ProfileCreator;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

@Getter
@Setter
@NoArgsConstructor
public class ParamClient<P extends SubjectProfile> extends BaseClient<P, Credentials> {
    private String paramName;

    public ParamClient(String name, String paramName, ProfileCreator<P, Credentials> profileCreator) {
        this.setName(name);
        this.paramName = paramName;
        this.setCredentialsExtractor(new ParamCredentialsExtractor(this.paramName));
        this.setProfileCreator(profileCreator);
    }


    @Override
    public String getSessionIdKey(ServletRequest request) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        return httpServletRequest.getHeader(this.paramName);
    }

    @Override
    public boolean isSupport(ServletRequest request) {
        boolean clientNameInUrl = super.isSupport(request);
        if (clientNameInUrl) {
            return true;
        } else {
            return this.getCredentialsExtractor().extract(request) != null;
        }
    }

    @Override
    public void init() {
        super.init();
        Assert.notNull(this.getName(), "name can not be null");
        Assert.notNull(this.paramName, "paramName can not be null");
    }
}
