package io.datalens.identity;

import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.KeycloakSessionUtil;

/** Report only our failed intent before Keycloak's priority-1 session closer runs. */
@Provider
@PreMatching
@Priority(20)
public class OutboxFailureFilter implements ContainerResponseFilter {
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
        if (session == null || session.isClosed()
                || !Boolean.TRUE.equals(session.getAttribute(OutboxListener.FAILURE_ATTRIBUTE))) return;
        session.getTransactionManager().setRollbackOnly();
        response.setStatus(500);
        response.setEntity(Map.of("error", "identity_event_persistence_failed"));
        response.getHeaders().putSingle(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);
        response.getHeaders().putSingle(HttpHeaders.CACHE_CONTROL, "no-store");
        response.getHeaders().remove(HttpHeaders.CONTENT_LENGTH);
    }
}
