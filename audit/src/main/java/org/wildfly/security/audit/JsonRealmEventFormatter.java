/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.audit;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.security.Principal;

import javax.json.JsonObjectBuilder;
import javax.json.spi.JsonProvider;

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.event.RealmAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.auth.server.event.RealmEventVisitor;
import org.wildfly.security.auth.server.event.RealmIdentityAuthorizationEvent;
import org.wildfly.security.authz.AuthorizationIdentity;

/**
 * A formatter for realm events that converts events into JSON strings.
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class JsonRealmEventFormatter extends RealmEventVisitor<Void, String> {

    private final JsonProvider jsonProvider;

    JsonRealmEventFormatter() {
        this.jsonProvider = JsonProvider.provider();
    }

    @Override
    public String handleUnknownEvent(RealmEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleUnknownEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleUnknownEvent(RealmEvent event, JsonObjectBuilder objectBuilder) {
        objectBuilder.add("event", event.getClass().getSimpleName());
    }

    @Override
    public String handleAuthenticationEvent(RealmAuthenticationEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleAuthenticationEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleAuthenticationEvent(RealmAuthenticationEvent event, JsonObjectBuilder objectBuilder) {
        handleUnknownEvent(event, objectBuilder);

        boolean success = event.isSuccess();
        objectBuilder.add("definite-success", success);

        boolean failure = event.isFailure();
        objectBuilder.add("definite-failure", failure);

        // identity or principal?
        RealmIdentity realmIdentity = event.getRealmIdentity();
        JsonObjectBuilder identityBuilder = jsonProvider.createObjectBuilder();
        identityBuilder.add("name", realmIdentity.getRealmIdentityPrincipal().getName());
        objectBuilder.add("principal", identityBuilder);
    }

    @Override
    public String handleAuthorizationEvent(RealmAuthorizationEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleAuthorizationEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleAuthorizationEvent(RealmAuthorizationEvent event, JsonObjectBuilder objectBuilder) {
        handleUnknownEvent(event, objectBuilder);

        boolean authorized = event.isAuthorized();
        objectBuilder.add("authorized", authorized);

        AuthorizationIdentity authorizationIdentity = event.getAuthorizationIdentity();
        JsonObjectBuilder identityBuilder = jsonProvider.createObjectBuilder();
        identityBuilder.add("name", authorizationIdentity.toString());
        objectBuilder.add("identity", identityBuilder);

        Principal principal = event.getPrincipal();
        JsonObjectBuilder principalBuilder = jsonProvider.createObjectBuilder();
        principalBuilder.add("name", principal.getName());
        objectBuilder.add("principal", principalBuilder);
    }

    @Override
    public String handleIdentityAuthorizationEvent(RealmIdentityAuthorizationEvent event, Void param) {
        checkNotNullParam("event", event);
        JsonObjectBuilder objectBuilder = jsonProvider.createObjectBuilder();
        handleIdentityAuthorizationEvent(event, objectBuilder);
        return objectBuilder.build().toString();
    }

    private void handleIdentityAuthorizationEvent(RealmIdentityAuthorizationEvent event, JsonObjectBuilder objectBuilder) {
        handleAuthorizationEvent(event, objectBuilder);

        Principal newPrincipal = event.getNewPrincipal();
        JsonObjectBuilder principalBuilder = jsonProvider.createObjectBuilder();
        principalBuilder.add("name", newPrincipal.getName());
        objectBuilder.add("new-principal", principalBuilder);
    }

    /**
     * Obtain a new {@link Builder} capable of building a {@link JsonRealmEventFormatter}.
     *
     * @return a new {@link Builder} capable of building a {@link JsonRealmEventFormatter}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for JSON realm event formatter.
     */
    public static class Builder {
        Builder() {
        }

        /**
         * Build a new {@link RealmEventVisitor} which will convert events into human-readable strings.
         * <p>
         * Once built the Builder can continue to be configured to create additional instances.
         *
         * @return a new {@link RealmEventVisitor} which will convert events into human-readable strings
         */
        public RealmEventVisitor<Void, String> build() {
            return new JsonRealmEventFormatter();
        }

    }
}
