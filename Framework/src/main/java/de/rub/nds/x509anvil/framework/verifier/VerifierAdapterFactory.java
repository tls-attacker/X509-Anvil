/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier;

import de.rub.nds.x509anvil.framework.verifier.tlsclientauth.TlsClientAuthVerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.tlsclientauth.TlsClientAuthVerifierAdapterConfig;

public class VerifierAdapterFactory {
    public static VerifierAdapter getInstance(VerifierAdapterType verifierAdapterType,
        VerifierAdapterConfig verifierAdapterConfig) {
        switch (verifierAdapterType) {
            case TLS_CLIENT_AUTH:
                if (!(verifierAdapterConfig instanceof TlsClientAuthVerifierAdapterConfig)) {
                    throw new UnsupportedOperationException("VerifierAdapterConfig does not match VerifierAdapterType");
                }
                TlsClientAuthVerifierAdapterConfig tlsClientAuthVerifierAdapterConfig =
                    (TlsClientAuthVerifierAdapterConfig) verifierAdapterConfig;
                return TlsClientAuthVerifierAdapter.fromConfig(tlsClientAuthVerifierAdapterConfig);

            default:
                throw new UnsupportedOperationException("Unsupported VerifierAdapterType");
        }
    }
}
