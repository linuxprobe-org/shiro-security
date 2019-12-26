package org.linuxprobe.shiro.security.client.finder;

import org.linuxprobe.shiro.security.client.Client;

import javax.servlet.ServletRequest;
import java.util.List;

/**
 * 查找请求的client
 */
public interface ClientFinder {
    Client<?> find(ServletRequest request, String defaultClient, List<Client<?>> clients);
}
