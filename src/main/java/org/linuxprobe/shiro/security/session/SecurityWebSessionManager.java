package org.linuxprobe.shiro.security.session;

import lombok.Getter;
import lombok.Setter;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.linuxprobe.shiro.security.client.Client;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;
import java.util.List;

@Getter
@Setter
public class SecurityWebSessionManager extends DefaultWebSessionManager {
    private SessionKeyStore sessionKeyStore;
    private List<Client<?>> clients;

    public SecurityWebSessionManager(SessionKeyStore sessionKeyStore, List<Client<?>> clients) {
        this.sessionKeyStore = sessionKeyStore;
        this.clients = clients;
    }


    private String getSessionIdKey(ServletRequest request) {
        for (Client<?> client : this.clients) {
            String sessionIdKey = client.getSessionIdKey(request);
            if (sessionIdKey != null) {
                return sessionIdKey;
            }
        }
        return null;
    }

    @Override
    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        Serializable sessionId = null;
        String sessionIdKey = this.getSessionIdKey(request);
        if (sessionIdKey != null) {
            sessionId = this.sessionKeyStore.getSessionIdByKey(sessionIdKey);
        }
        if (sessionId == null) {
            sessionId = super.getSessionId(request, response);
        }
        return sessionId;
    }
}
