package io.datalens.identity;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class OutboxListenerFactory implements EventListenerProviderFactory {
    public EventListenerProvider create(KeycloakSession session) {
        return new OutboxListener(session);
    }
    public String getId() { return "identity-outbox-proof"; }
    public void init(Config.Scope config) {}
    public void postInit(KeycloakSessionFactory factory) {}
    public void close() {}
}
