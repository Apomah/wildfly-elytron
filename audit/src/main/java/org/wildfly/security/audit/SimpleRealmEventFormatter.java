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

import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.event.RealmAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.auth.server.event.RealmEventVisitor;
import org.wildfly.security.auth.server.event.RealmIdentityAuthorizationEvent;
import org.wildfly.security.authz.AuthorizationIdentity;

/**
 * A formatter for realm events that converts events into human-readable strings.
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class SimpleRealmEventFormatter extends RealmEventVisitor<Void, String> {

    SimpleRealmEventFormatter() {
    }

    @Override
    public String handleUnknownEvent(RealmEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleUnknownEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleUnknownEvent(RealmEvent event, StringBuilder stringBuilder) {
        stringBuilder.append("event=").append(event.getClass().getSimpleName());
    }

    @Override
    public String handleAuthenticationEvent(RealmAuthenticationEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleAuthenticationEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleAuthenticationEvent(RealmAuthenticationEvent event, StringBuilder stringBuilder) {
        handleUnknownEvent(event, stringBuilder);

        boolean success = event.isSuccess();
        stringBuilder.append(",definite-success=").append(success);

        boolean failure = event.isFailure();
        stringBuilder.append(",definite-failure=").append(failure);

        // identity or principal?
        RealmIdentity realmIdentity = event.getRealmIdentity();
        stringBuilder.append(",principal=[name=").append(realmIdentity.getRealmIdentityPrincipal().getName()).append(']');
    }

    @Override
    public String handleAuthorizationEvent(RealmAuthorizationEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleAuthorizationEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleAuthorizationEvent(RealmAuthorizationEvent event, StringBuilder stringBuilder) {
        handleUnknownEvent(event, stringBuilder);

        boolean authorized = event.isAuthorized();
        stringBuilder.append(",authorized=").append(authorized);

        AuthorizationIdentity authorizationIdentity = event.getAuthorizationIdentity();
        stringBuilder.append(",identity=[name=").append(authorizationIdentity).append(']');

        Principal principal = event.getPrincipal();
        stringBuilder.append(",principal=[name=").append(principal.getName()).append(']');
    }

    @Override
    public String handleIdentityAuthorizationEvent(RealmIdentityAuthorizationEvent event, Void param) {
        checkNotNullParam("event", event);
        StringBuilder stringBuilder = new StringBuilder("{");
        handleIdentityAuthorizationEvent(event, stringBuilder);
        return stringBuilder.append('}').toString();
    }

    private void handleIdentityAuthorizationEvent(RealmIdentityAuthorizationEvent event, StringBuilder stringBuilder) {
        handleAuthorizationEvent(event, stringBuilder);

        Principal newPrincipal = event.getNewPrincipal();
        stringBuilder.append(",new-principal=[name=").append(newPrincipal.getName()).append(']');
    }

    /**
     * Create a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for simple realm event formatter.
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
            return new SimpleRealmEventFormatter();
        }

    }
}
