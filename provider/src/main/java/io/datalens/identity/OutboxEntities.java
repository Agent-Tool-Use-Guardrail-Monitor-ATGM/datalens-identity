package io.datalens.identity;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class OutboxEntities implements JpaEntityProviderFactory {
    public JpaEntityProvider create(KeycloakSession session) {
        return new JpaEntityProvider() {
            public List<Class<?>> getEntities() { return List.of(OutboxRecord.class); }
            public String getChangelogLocation() { return "META-INF/identity-outbox.xml"; }
            public String getFactoryId() { return getId(); }
            public void close() {}
        };
    }

    public String getId() { return "identity-outbox"; }
    public void init(Config.Scope config) {}
    public void postInit(KeycloakSessionFactory factory) {}
    public void close() {}
}
