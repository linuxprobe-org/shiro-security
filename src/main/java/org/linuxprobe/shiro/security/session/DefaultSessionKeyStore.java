package org.linuxprobe.shiro.security.session;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.util.concurrent.TimeUnit;

/**
 * 默认缓存,不能为每个key单独设置过期时间
 */
public class DefaultSessionKeyStore implements SessionKeyStore {
    private Cache<String, String> cache;

    /**
     * 构造函数
     *
     * @param timeout 设置全局过期时间, 单位毫秒
     */
    public DefaultSessionKeyStore(long timeout) {
        this.cache = CacheBuilder.newBuilder()
                .maximumSize(100000000) // 设置缓存的最大容量
                .expireAfterWrite(timeout, TimeUnit.MILLISECONDS) // 设置缓存在写入一分钟后失效
                .concurrencyLevel(3000) // 设置并发级别为3000
                .recordStats() // 开启缓存统计
                .build();
    }

    @Override
    public String getSessionIdByKey(String key) {
        return this.cache.getIfPresent(key);
    }

    @Override
    public void addMap(String key, String sessionId, long timeout, TimeUnit timeUnit) {
        this.cache.put(key, sessionId);
        this.cache.put(sessionId, key);
    }


    @Override
    public void deleteMapBySessionId(String sessionId) {
        String key = this.cache.getIfPresent(sessionId);
        if (key != null) {
            this.cache.invalidate(sessionId);
            this.cache.invalidate(key);
        }
    }
}
