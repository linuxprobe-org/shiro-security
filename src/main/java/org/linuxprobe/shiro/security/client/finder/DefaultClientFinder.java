package org.linuxprobe.shiro.security.client.finder;

import org.linuxprobe.shiro.security.client.Client;

import javax.servlet.ServletRequest;
import java.util.List;

public class DefaultClientFinder implements ClientFinder {
    private DefaultClientFinder() {
    }

    private static DefaultClientFinder instance = new DefaultClientFinder();

    public static DefaultClientFinder getInstance() {
        return DefaultClientFinder.instance;
    }

    @Override
    public Client<?> find(ServletRequest request, String defaultClient, List<Client<?>> clients) {
        Client<?> currentClient = null;
        for (Client client : clients) {
            if (client.isSupport(request)) {
                currentClient = client;
            }
        }
        if (currentClient == null && defaultClient != null && !defaultClient.isEmpty()) {
            for (Client client : clients) {
                if (defaultClient.equals(client.getName())) {
                    currentClient = client;
                    break;
                }
            }
        }
        return currentClient;
    }
}
