package io.datalens.identity;

import jakarta.ws.rs.NotFoundException;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public final class IdentityBackfillProvider implements AdminRealmResourceProviderFactory, AdminRealmResourceProvider {
    public String getId() { return "identity-backfill"; }
    public AdminRealmResourceProvider create(KeycloakSession session) { return this; }
    public void init(Config.Scope config) {}
    public void postInit(KeycloakSessionFactory factory) {}
    public void close() {}

    public Object getResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        auth.users().requireManage();
        if (!realm.getEventsListenersStream().anyMatch(OutboxListenerFactory.ID::equals)) {
            throw new NotFoundException();
        }
        return new IdentityBackfillResource(session, realm);
    }
}
