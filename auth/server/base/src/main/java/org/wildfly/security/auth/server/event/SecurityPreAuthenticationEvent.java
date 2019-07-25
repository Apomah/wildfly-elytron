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
package org.wildfly.security.auth.server.event;

import java.security.Principal;

import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * An event to represent that an authentication is about to happen.
 *
 * @author <a href="mailto:jucook@redhat.com">Justin Cook</a>
 */
public class SecurityPreAuthenticationEvent extends SecurityEvent {

    private final Principal principal;

    /**
     * @param securityIdentity the {@link SecurityIdentity} that is about to attempt authentication.
     */
    public SecurityPreAuthenticationEvent(SecurityIdentity securityIdentity, Principal principal) {
        super(securityIdentity);
        this.principal = principal;
    }

    /**
     * Gets the principal used to the failed authentication.
     *
     * @return the principal used to that failed authentication (filled event if identity does not exists)
     */
    public Principal getPrincipal() {
        return principal;
    }

    @Override
    public <P, R> R accept(SecurityEventVisitor<P, R> visitor, P param) {
        return visitor.handlePreAuthenticationEvent(this, param);
    }
}
