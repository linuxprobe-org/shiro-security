package org.linuxprobe.shiro.security.session;

import org.linuxprobe.luava.cache.impl.DefaultCache;

import java.util.concurrent.TimeUnit;

public class DefaultSessionKeyStore implements SessionKeyStore {
    private static final String keyMapSessionIdPrefix = "shiro:keyMapSessionId:";
    private static final String sessionIdMapKeyPrefix = "shiro:sessionIdMapKey:";
    private DefaultCache cache = new DefaultCache();

    @Override
    public String getSessionIdByKey(String key) {
        return this.cache.get(DefaultSessionKeyStore.keyMapSessionIdPrefix + key);
    }

    @Override
    public void addMap(String key, String sessionId, long timeout, TimeUnit timeUnit) {
        this.cache.set(DefaultSessionKeyStore.keyMapSessionIdPrefix + key, sessionId, timeout, timeUnit);
        this.cache.set(DefaultSessionKeyStore.sessionIdMapKeyPrefix + sessionId, key, timeout, timeUnit);
    }


    @Override
    public void deleteMapBySessionId(String sessionId) {
        String key = this.cache.get(DefaultSessionKeyStore.sessionIdMapKeyPrefix + sessionId);
        if (key != null) {
            this.cache.delete(DefaultSessionKeyStore.sessionIdMapKeyPrefix + sessionId);
            this.cache.delete(DefaultSessionKeyStore.keyMapSessionIdPrefix + key);
        }
    }
}
