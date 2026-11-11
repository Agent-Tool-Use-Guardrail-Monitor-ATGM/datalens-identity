package io.datalens.identity;

import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.PathSegment;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;

/** Keycloak's successful USER_SESSION delete event arrives after the target is removed. */
@Provider
public class AdminSessionTargetFilter implements ContainerRequestFilter {
    static final String TARGET = AdminSessionTargetFilter.class.getName();

    record Target(String realmId, String sessionId, String subject, String onlineSessionId) {}

    @Inject
    KeycloakSession session;

    @Override
    public void filter(ContainerRequestContext request) {
        if (!request.getMethod().equals("DELETE")) return;
        var path = request.getUriInfo().getPathSegments().stream().map(PathSegment::getPath).toList();
        if (path.size() != 5 || !path.get(0).equals("admin") || !path.get(1).equals("realms")
                || !path.get(3).equals("sessions")) return;
        var realm = session.realms().getRealmByName(path.get(2));
        if (realm == null) return;
        String id = path.get(4);
        boolean offline = Boolean.parseBoolean(request.getUriInfo().getQueryParameters().getFirst("isOffline"));
        UserSessionModel target = offline ? session.sessions().getOfflineUserSession(realm, id)
                : session.sessions().getUserSession(realm, id);
        if (target == null || target.getUser() == null) return;
        String onlineId = offline ? target.getNote(UserSessionModel.CORRESPONDING_SESSION_ID) : null;
        // The listener uses this only after Keycloak authorizes and completes the matching operation.
        session.setAttribute(TARGET, new Target(realm.getId(), id, target.getUser().getId(), onlineId));
    }
}
