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

import static org.junit.Assert.assertTrue;

import java.security.Principal;

import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.security.auth.principal.AnonymousPrincipal;
import org.wildfly.security.auth.principal.NumericPrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.event.RealmAbandonedAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmEvent;
import org.wildfly.security.auth.server.event.RealmEventVisitor;
import org.wildfly.security.auth.server.event.RealmFailedAuthenticationEvent;
import org.wildfly.security.auth.server.event.RealmIdentityFailedAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmIdentitySuccessfulAuthorizationEvent;
import org.wildfly.security.auth.server.event.RealmSuccessfulAuthenticationEvent;
import org.wildfly.security.authz.AuthorizationIdentity;

/**
 * Test case to test the SimpleRealmEventFormatter
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class SimpleRealmEventFormatterTest {

    private static RealmEventVisitor<?, String> simpleFormatter;
    private static RealmIdentity realmIdentity = RealmIdentity.ANONYMOUS;
    private static AuthorizationIdentity authorizationIdentity = AuthorizationIdentity.EMPTY;
    private static Principal principal = AnonymousPrincipal.getInstance();
    private static Principal newPrincipal = new NumericPrincipal(1);

    @BeforeClass
    public static void createDomain() {
        simpleFormatter = SimpleRealmEventFormatter.builder().build();
    }

    private String baseTest(RealmEvent event, String eventName) {
        String formatted = event.accept(simpleFormatter, null);

        assertTrue("Event", formatted.contains("event=" + eventName));

        return formatted;
    }

    @Test
    public void testAuthenticationAbandoned() {
        String formatted = baseTest(new RealmAbandonedAuthenticationEvent(realmIdentity), "RealmAbandonedAuthenticationEvent");

        assertTrue("Principal", formatted.contains("name=anonymous"));
        assertTrue("Success", formatted.contains("definite-success=false"));
        assertTrue("Failure", formatted.contains("definite-failure=false"));
    }

    @Test
    public void testAuthenticationFailed() {
        String formatted = baseTest(new RealmFailedAuthenticationEvent(realmIdentity, null, null), "RealmFailedAuthenticationEvent");

        assertTrue("Principal", formatted.contains("name=anonymous"));
        assertTrue("Success", formatted.contains("definite-success=false"));
        assertTrue("Failure", formatted.contains("definite-failure=true"));
    }

    @Test
    public void testAuthenticationSuccessful() {
        String formatted = baseTest(new RealmSuccessfulAuthenticationEvent(realmIdentity, authorizationIdentity, null, null), "RealmSuccessfulAuthenticationEvent");

        assertTrue("Principal", formatted.contains("name=anonymous"));
        assertTrue("Success", formatted.contains("definite-success=true"));
        assertTrue("Failure", formatted.contains("definite-failure=false"));
    }

    @Test
    public void testAuthorizationFailed() {
        String formatted = baseTest(new RealmIdentityFailedAuthorizationEvent(authorizationIdentity, principal, newPrincipal), "RealmIdentityFailedAuthorizationEvent");

        assertTrue("Authorized", formatted.contains("authorized=false"));
        assertTrue("Principal", formatted.contains("name=anonymous"));
        assertTrue("New Principal", formatted.contains("name=1"));
        assertTrue("Identity", formatted.contains("name=EMPTY"));
    }

    @Test
    public void testAuthorizationSuccessful() {
        String formatted = baseTest(new RealmIdentitySuccessfulAuthorizationEvent(authorizationIdentity, principal, newPrincipal), "RealmIdentitySuccessfulAuthorizationEvent");

        assertTrue("Authorized", formatted.contains("authorized=true"));
        assertTrue("Principal", formatted.contains("name=anonymous"));
        assertTrue("New Principal", formatted.contains("name=1"));
        assertTrue("Identity", formatted.contains("name=EMPTY"));
    }
}
