/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.sasl.digest;

import java.nio.charset.Charset;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.sasl.WildFlySasl;
import org.wildfly.security.sasl.util.Charsets;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
@MetaInfServices(value = SaslClientFactory.class)
public class DigestClientFactory extends AbstractDigestFactory implements SaslClientFactory {

    public DigestClientFactory() {
    }

    /* (non-Javadoc)
     * @see javax.security.sasl.SaslClientFactory#createSaslClient(java.lang.String[], java.lang.String, java.lang.String, java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
     */
    @Override
    public SaslClient createSaslClient(String[] mechanisms, String authorizationId, String protocol, String serverName,
            Map<String, ?> props, CallbackHandler cbh) throws SaslException {

        if (! matches(props)) return null;
        String selectedMech = select(mechanisms);
        if (selectedMech == null) return null;

        Boolean utf8 = (Boolean)props.get(WildFlySasl.USE_UTF8);
        Charset charset = (utf8==null || utf8.booleanValue()) ? Charsets.UTF_8 : Charsets.LATIN_1;

        String supportedCipherOpts = (String)props.get(WildFlySasl.SUPPORTED_CIPHER_NAMES);
        String[] ciphers = (supportedCipherOpts == null ? null : supportedCipherOpts.split(","));

        final DigestSaslClient client = new DigestSaslClient(selectedMech, protocol, serverName, cbh, authorizationId, false, charset, ciphers);
        client.init();
        return client;
    }
}
