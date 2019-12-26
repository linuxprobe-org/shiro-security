package org.linuxprobe.shiro.security.session;

import java.util.concurrent.TimeUnit;

public interface SessionKeyStore {
    /**
     * 根据key获取sessionId
     */
    String getSessionIdByKey(String token);

    /**
     * 增加映射
     */
    void addMap(String key, String sessionId, long timeout, TimeUnit timeUnit);

    /**
     * 根据sessionId删除映射
     */
    void deleteMapBySessionId(String sessionId);
}
