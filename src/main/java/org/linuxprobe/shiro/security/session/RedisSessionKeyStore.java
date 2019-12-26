package org.linuxprobe.shiro.security.session;

import org.linuxprobe.luava.cache.impl.redis.RedisCache;

import java.util.concurrent.TimeUnit;

public class RedisSessionKeyStore implements SessionKeyStore {
    private static final String keyMapSessionIdPrefix = "shiro:keyMapSessionId:";
    private static final String sessionIdMapKeyPrefix = "shiro:sessionIdMapKey:";
    private RedisCache redisCache;

    public RedisSessionKeyStore(RedisCache redisCache) {
        this.redisCache = redisCache;
    }

    @Override
    public String getSessionIdByKey(String key) {
        return this.redisCache.get(RedisSessionKeyStore.keyMapSessionIdPrefix + key);
    }

    @Override
    public void addMap(String key, String sessionId, long timeout, TimeUnit timeUnit) {
        this.redisCache.set(RedisSessionKeyStore.keyMapSessionIdPrefix + key, sessionId, timeout, timeUnit);
        this.redisCache.set(RedisSessionKeyStore.sessionIdMapKeyPrefix + sessionId, key, timeout, timeUnit);
    }


    @Override
    public void deleteMapBySessionId(String sessionId) {
        String key = this.redisCache.get(RedisSessionKeyStore.sessionIdMapKeyPrefix + sessionId);
        if (key != null) {
            this.redisCache.delete(RedisSessionKeyStore.sessionIdMapKeyPrefix + sessionId);
            this.redisCache.delete(RedisSessionKeyStore.keyMapSessionIdPrefix + key);
        }
    }
}
