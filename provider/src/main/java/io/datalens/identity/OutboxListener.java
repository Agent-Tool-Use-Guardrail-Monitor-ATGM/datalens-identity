package io.datalens.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.UUID;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.urls.UrlType;

/** Transaction proof only: not a complete production identity-change listener. */
public class OutboxListener implements EventListenerProvider {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final KeycloakSession session;

    public OutboxListener(KeycloakSession session) { this.session = session; }

    public void onEvent(Event event) {
        if (event.getError() == null && event.getType() == EventType.REGISTER) {
            record(event.getRealmId(), event.getUserId(), "user.created");
        }
    }

    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event.getError() != null || event.getResourceType() != ResourceType.USER
                || event.getResourcePath() == null) return;
        String[] path = event.getResourcePath().split("/");
        if (path.length != 2 || !path[0].equals("users")) return;
        if (event.getOperationType() == OperationType.CREATE) {
            record(event.getRealmId(), path[1], "user.created");
        } else if (event.getOperationType() == OperationType.UPDATE) {
            record(event.getRealmId(), path[1], "user.profile.updated");
        }
    }

    private void record(String realmId, String subject, String eventType) {
        try {
            RealmModel realm = session.realms().getRealm(realmId);
            UserModel user = session.users().getUserById(realm, subject);
            if (user == null) throw new IllegalStateException("Missing account snapshot");
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            // PostgreSQL coordinates first-writer races and increments in this same transaction.
            Number revision = (Number) em.createNativeQuery("""
                INSERT INTO dl_identity_revision (realm_id, subject, profile_revision, security_revision)
                VALUES (:realm, :subject, 1, 0)
                ON CONFLICT (realm_id, subject) DO UPDATE
                SET profile_revision = dl_identity_revision.profile_revision + 1
                RETURNING profile_revision
                """)
                .setParameter("realm", realmId).setParameter("subject", subject).getSingleResult();
            var data = new LinkedHashMap<String, Object>();
            data.put("profile_revision", revision.longValue());
            String name = ((user.getFirstName() == null ? "" : user.getFirstName()) + " "
                    + (user.getLastName() == null ? "" : user.getLastName())).trim();
            data.put("display_name", name.isEmpty() ? null : name);
            data.put("username", user.getUsername());
            data.put("email", user.getEmail());
            checkDisplay((String) data.get("display_name"), 256);
            checkDisplay(user.getUsername(), 256);
            checkDisplay(user.getEmail(), 320);
            Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
            OutboxRecord record = new OutboxRecord();
            record.eventId = UUID.randomUUID().toString();
            record.realmId = realmId;
            record.subject = subject;
            record.createdAtMs = now.toEpochMilli();
            var envelope = new LinkedHashMap<String, Object>();
            envelope.put("schema_version", 1);
            envelope.put("event_id", record.eventId);
            envelope.put("event_type", eventType);
            envelope.put("issuer", session.getContext().getUri(UrlType.FRONTEND)
                    .getBaseUriBuilder().path("realms").path(realm.getName()).build().toString());
            envelope.put("subject", subject);
            envelope.put("occurred_at", now.toString());
            envelope.put("data", data);
            record.payload = JSON.writeValueAsString(envelope);
            if (record.payload.getBytes(StandardCharsets.UTF_8).length > 16384)
                throw new IllegalStateException("Identity event exceeds limit");
            em.persist(record);
            em.flush();
        } catch (Exception failure) {
            // Listener errors are swallowed; prepare must fail before any main transaction commits.
            session.getTransactionManager().enlistPrepare(new AbstractKeycloakTransaction() {
                protected void commitImpl() {
                    throw new IllegalStateException("Identity outbox persistence failed");
                }
                protected void rollbackImpl() {}
            });
            session.getTransactionManager().setRollbackOnly();
            throw new IllegalStateException("Identity outbox persistence failed");
        }
    }

    private static void checkDisplay(String value, int maximum) {
        if (value != null && (value.codePointCount(0, value.length()) > maximum
                || value.codePoints().anyMatch(c -> c < 32 || c == 127
                    || (c >= 0xD800 && c <= 0xDFFF)))) {
            throw new IllegalStateException("Identity display field violates contract");
        }
    }

    public void close() {}
}
