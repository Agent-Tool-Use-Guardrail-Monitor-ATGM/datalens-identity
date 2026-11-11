package io.datalens.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.keycloak.common.util.Time;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.Details;
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

/** Identity event capture for the disposable Keycloak image. */
public class OutboxListener implements EventListenerProvider {
    static final String FAILURE_ATTRIBUTE = "io.datalens.identity.outbox.failed";
    private static final ObjectMapper JSON = new ObjectMapper();
    private final KeycloakSession session;

    public OutboxListener(KeycloakSession session) { this.session = session; }

    public void onEvent(Event event) {
        if (event.getError() != null) return;
        if (event.getType() == EventType.REGISTER) {
            record(event.getRealmId(), event.getUserId(), "user.created");
        } else if (event.getType() == EventType.UPDATE_PROFILE) {
            record(event.getRealmId(), event.getUserId(), "user.profile.updated");
        } else if (event.getType() == EventType.LOGOUT
                && event.getUserId() != null && event.getSessionId() != null) {
            record(event.getRealmId(), event.getUserId(), "user.session.revoked",
                    Map.of("session_id", event.getSessionId(), "reason", "logout"));
        }
    }

    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (event.getError() != null || event.getResourcePath() == null) return;
        String realmId = event.getRealmId();
        ResourceType resource = event.getResourceType();
        OperationType operation = event.getOperationType();
        String[] path = event.getResourcePath().split("/");
        if (resource == ResourceType.USER_SESSION && operation == OperationType.DELETE
                && path.length == 2 && path[0].equals("sessions")) {
            var target = session.getAttribute(AdminSessionTargetFilter.TARGET, AdminSessionTargetFilter.Target.class);
            if (target == null || !realmId.equals(target.realmId()) || !path[1].equals(target.sessionId())) {
                throw failTransaction();
            }
            record(realmId, target.subject(), "user.session.revoked",
                    Map.of("session_id", path[1], "reason", "admin_session_logout"));
            if (target.onlineSessionId() != null && !path[1].equals(target.onlineSessionId())) {
                record(realmId, target.subject(), "user.session.revoked",
                        Map.of("session_id", target.onlineSessionId(), "reason", "admin_session_logout"));
            }
            return;
        }
        if (path.length < 2 || !path[0].equals("users")) return;
        String subject = path[1];
        if (resource == ResourceType.USER && path.length == 2) {
            if (operation == OperationType.CREATE) {
                record(realmId, subject, "user.created");
            } else if (operation == OperationType.UPDATE) {
                record(realmId, subject, "user.profile.updated");
                var details = event.getDetails();
                if (details != null && details.containsKey(Details.PREVIOUS_ENABLED)) {
                    boolean enabled = Boolean.parseBoolean(details.get(Details.UPDATED_ENABLED));
                    record(realmId, subject, enabled ? "user.enabled" : "user.disabled", Map.of());
                }
            } else if (operation == OperationType.DELETE) {
                record(realmId, subject, "user.deleted", Map.of());
            }
        } else if (resource == ResourceType.USER && operation == OperationType.ACTION
                && path.length == 3 && path[2].equals("logout")) {
            record(realmId, subject, "user.sessions.revoked", Map.of("reason", "logout_all"));
        } else if ((operation == OperationType.CREATE || operation == OperationType.DELETE)
                && path.length >= 4 && path[2].equals("role-mappings")
                && ((resource == ResourceType.REALM_ROLE_MAPPING && path.length == 4 && path[3].equals("realm"))
                || (resource == ResourceType.CLIENT_ROLE_MAPPING && path.length == 5 && path[3].equals("clients")))) {
            record(realmId, subject, "user.sessions.revoked", Map.of("reason", "roles_changed"));
        }
    }

    private void record(String realmId, String subject, String eventType) {
        record(realmId, subject, eventType, null);
    }

    private void record(String realmId, String subject, String eventType, Map<String, String> securityData) {
        try {
            RealmModel realm = session.realms().getRealm(realmId);
            EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
            boolean profile = securityData == null;
            String counter = profile ? "profile_revision" : "security_revision";
            // PostgreSQL coordinates first-writer races and increments in this same transaction.
            Number revision = (Number) em.createNativeQuery("""
                INSERT INTO dl_identity_revision (realm_id, subject, profile_revision, security_revision)
                VALUES (:realm, :subject, :profile, :security)
                ON CONFLICT (realm_id, subject) DO UPDATE
                SET %1$s = dl_identity_revision.%1$s + 1
                RETURNING %1$s
                """.formatted(counter))
                .setParameter("realm", realmId).setParameter("subject", subject)
                .setParameter("profile", profile ? 1L : 0L).setParameter("security", profile ? 0L : 1L)
                .getSingleResult();
            var data = new LinkedHashMap<String, Object>();
            data.put(counter, revision.longValue());
            Instant now = profile ? Instant.now().truncatedTo(ChronoUnit.MICROS)
                    : Instant.ofEpochMilli(Time.currentTimeMillis());
            if (profile) {
                addProfile(data, session.users().getUserById(realm, subject));
            } else {
                checkDisplay(securityData.get("session_id"), 255);
                data.putAll(securityData);
                if (eventType.equals("user.sessions.revoked") || eventType.equals("user.disabled")
                        || eventType.equals("user.deleted")) {
                    data.put("tokens_issued_at_or_before", now.getEpochSecond());
                }
            }
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
            throw failTransaction();
        }
    }

    private static void addProfile(Map<String, Object> data, UserModel user) {
        if (user == null) throw new IllegalStateException("Missing account snapshot");
        String name = ((user.getFirstName() == null ? "" : user.getFirstName()) + " "
                + (user.getLastName() == null ? "" : user.getLastName())).trim();
        checkDisplay(name, 256);
        checkDisplay(user.getUsername(), 256);
        checkDisplay(user.getEmail(), 320);
        data.put("display_name", name.isEmpty() ? null : name);
        data.put("username", user.getUsername());
        data.put("email", user.getEmail());
    }

    private IllegalStateException failTransaction() {
        session.setAttribute(FAILURE_ATTRIBUTE, Boolean.TRUE);
        // Listener errors are swallowed; prepare must fail before any main transaction commits.
        session.getTransactionManager().enlistPrepare(new AbstractKeycloakTransaction() {
            protected void commitImpl() {
                throw new IllegalStateException("Identity outbox persistence failed");
            }
            protected void rollbackImpl() {}
        });
        session.getTransactionManager().setRollbackOnly();
        return new IllegalStateException("Identity outbox persistence failed");
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
