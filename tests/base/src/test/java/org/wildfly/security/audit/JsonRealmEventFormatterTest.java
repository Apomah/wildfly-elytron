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

import static org.junit.Assert.assertEquals;

import java.io.StringReader;
import java.security.Principal;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

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
 * Test case to test the JsonRealmEventFormatter
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class JsonRealmEventFormatterTest {
    private static RealmEventVisitor<?, String> jsonFormatter;
    private static RealmIdentity realmIdentity = RealmIdentity.ANONYMOUS;
    private static AuthorizationIdentity authorizationIdentity = AuthorizationIdentity.EMPTY;
    private static Principal principal = AnonymousPrincipal.getInstance();
    private static Principal newPrincipal = new NumericPrincipal(1);

    @BeforeClass
    public static void createDomain() {
        jsonFormatter = JsonRealmEventFormatter.builder().build();
    }

    private JsonObject baseTest(RealmEvent event, String eventName) {
        String formatted = event.accept(jsonFormatter, null);

        JsonReader reader = Json.createReader(new StringReader(formatted));
        JsonObject jsonObject = reader.readObject();

        assertEquals("Expected Event", eventName, jsonObject.getString("event"));

        return jsonObject;
    }

    @Test
    public void testAuthenticationAbandoned() {
        JsonObject jsonObject = baseTest(new RealmAbandonedAuthenticationEvent(realmIdentity), "RealmAbandonedAuthenticationEvent");

        assertEquals("Success", false, jsonObject.getBoolean("definite-success"));
        assertEquals("Failure", false, jsonObject.getBoolean("definite-failure"));
        JsonObject identity = jsonObject.getJsonObject("principal");
        assertEquals("Principal", "anonymous", identity.getString("name"));
    }

    @Test
    public void testAuthenticationFailed() {
        JsonObject jsonObject = baseTest(new RealmFailedAuthenticationEvent(realmIdentity, null, null), "RealmFailedAuthenticationEvent");

        assertEquals("Success", false, jsonObject.getBoolean("definite-success"));
        assertEquals("Failure", true, jsonObject.getBoolean("definite-failure"));
        JsonObject identity = jsonObject.getJsonObject("principal");
        assertEquals("Principal", "anonymous", identity.getString("name"));
    }

    @Test
    public void testAuthenticationSuccessful() {
        JsonObject jsonObject = baseTest(new RealmSuccessfulAuthenticationEvent(realmIdentity, authorizationIdentity, null, null), "RealmSuccessfulAuthenticationEvent");

        assertEquals("Success", true, jsonObject.getBoolean("definite-success"));
        assertEquals("Failure", false, jsonObject.getBoolean("definite-failure"));
        JsonObject identity = jsonObject.getJsonObject("principal");
        assertEquals("Principal", "anonymous", identity.getString("name"));
    }

    @Test
    public void testAuthorizationFailed() {
        JsonObject jsonObject = baseTest(new RealmIdentityFailedAuthorizationEvent(authorizationIdentity, principal, newPrincipal), "RealmIdentityFailedAuthorizationEvent");

        assertEquals("Authorized", false, jsonObject.getBoolean("authorized"));
        JsonObject principal = jsonObject.getJsonObject("principal");
        assertEquals("Principal", "anonymous", principal.getString("name"));
        JsonObject newPrincipal = jsonObject.getJsonObject("new-principal");
        assertEquals("New Principal", "1", newPrincipal.getString("name"));
        JsonObject identity = jsonObject.getJsonObject("identity");
        assertEquals("Identity", "EMPTY", identity.getString("name"));
    }

    @Test
    public void testAuthorizationSuccessful() {
        JsonObject jsonObject = baseTest(new RealmIdentitySuccessfulAuthorizationEvent(authorizationIdentity, principal, newPrincipal), "RealmIdentitySuccessfulAuthorizationEvent");

        assertEquals("Authorized", true, jsonObject.getBoolean("authorized"));
        JsonObject principal = jsonObject.getJsonObject("principal");
        assertEquals("Principal", "anonymous", principal.getString("name"));
        JsonObject newPrincipal = jsonObject.getJsonObject("new-principal");
        assertEquals("New Principal", "1", newPrincipal.getString("name"));
        JsonObject identity = jsonObject.getJsonObject("identity");
        assertEquals("Identity", "EMPTY", identity.getString("name"));
    }
}
