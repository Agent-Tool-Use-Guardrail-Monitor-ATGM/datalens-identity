package io.datalens.identity;

import jakarta.enterprise.inject.Vetoed;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.jpa.entities.UserEntity;

@Provider
@Vetoed
public class IdentityBackfillResource {
    private final KeycloakSession session;
    private final RealmModel realm;

    IdentityBackfillResource(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    @POST
    @Path("users/{subject}")
    public Response snapshot(@PathParam("subject") String subject) {
        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        // Serialize with local account writes before taking the outbox revision lock.
        UserEntity user = em.createQuery("""
                SELECT u FROM UserEntity u WHERE u.id = :subject AND u.realmId = :realm
                    AND u.federationLink IS NULL AND u.serviceAccountClientLink IS NULL
                """, UserEntity.class)
                .setParameter("subject", subject)
                .setParameter("realm", realm.getId())
                .setLockMode(LockModeType.PESSIMISTIC_WRITE)
                .getSingleResultOrNull();
        if (user == null) throw new NotFoundException();
        em.refresh(user);
        new OutboxListener(session).recordSnapshot(realm, user);
        session.getTransactionManager().commit();
        return Response.noContent().build();
    }
}
