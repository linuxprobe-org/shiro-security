package org.linuxprobe.shiro.security.session;

import org.apache.shiro.session.Session;
import org.linuxprobe.luava.cache.impl.redis.RedisCache;
import org.linuxprobe.luava.shiro.redis.session.ShiroRedisSessionDAO;

public class SecurityShiroRedisSessionDAO extends ShiroRedisSessionDAO {
    private SessionKeyStore sessionKeyStore;

    public SecurityShiroRedisSessionDAO(RedisCache redisCache, SessionKeyStore sessionKeyStore) {
        super(redisCache);
        this.sessionKeyStore = sessionKeyStore;
    }

    @Override
    public void delete(Session session) {
        super.delete(session);
        this.sessionKeyStore.deleteMapBySessionId(session.getId().toString());
    }
}
