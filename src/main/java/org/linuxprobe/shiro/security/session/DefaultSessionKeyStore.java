package org.linuxprobe.shiro.security.session;

import org.linuxprobe.luava.cache.impl.redis.RedisCache;

import java.util.concurrent.TimeUnit;

public class DefaultSessionKeyStore implements SessionKeyStore {
    private static final String keyMapSessionIdPrefix = "shiro:keyMapSessionId:";
    private static final String sessionIdMapKeyPrefix = "shiro:sessionIdMapKey:";
    private RedisCache redisCache;

    public DefaultSessionKeyStore(RedisCache redisCache) {
        this.redisCache = redisCache;
    }

    @Override
    public String getSessionIdByKey(String key) {
        return this.redisCache.get(DefaultSessionKeyStore.keyMapSessionIdPrefix + key);
    }

    @Override
    public void addMap(String key, String sessionId, long timeout, TimeUnit timeUnit) {
        this.redisCache.set(DefaultSessionKeyStore.keyMapSessionIdPrefix + key, sessionId, timeout, timeUnit);
        this.redisCache.set(DefaultSessionKeyStore.sessionIdMapKeyPrefix + sessionId, key, timeout, timeUnit);
    }


    @Override
    public void deleteMapBySessionId(String sessionId) {
        String key = this.redisCache.get(DefaultSessionKeyStore.sessionIdMapKeyPrefix + sessionId);
        if (key != null) {
            this.redisCache.delete(DefaultSessionKeyStore.sessionIdMapKeyPrefix + sessionId);
            this.redisCache.delete(DefaultSessionKeyStore.keyMapSessionIdPrefix + key);
        }
    }
}
