/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier;

import de.rub.nds.x509anvil.framework.verifier.adapter.TlsClientAuthVerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.adapter.TlsServerAuthVerifierAdapter;

public class VerifierAdapterFactory {
    public static VerifierAdapter getInstance(
            VerifierAdapterType verifierAdapterType, VerifierAdapterConfig verifierAdapterConfig) {
        return switch (verifierAdapterType) {
            case TLS_CLIENT_AUTH -> {
                if (!(verifierAdapterConfig
                        instanceof TlsAuthVerifierAdapterConfig tlsAuthVerifierAdapterConfig)) {
                    throw new UnsupportedOperationException(
                            "VerifierAdapterConfig does not match VerifierAdapterType");
                }
                yield TlsClientAuthVerifierAdapter.fromConfig(tlsAuthVerifierAdapterConfig);
            }
            case TLS_SERVER_AUTH -> {
                if (!(verifierAdapterConfig
                        instanceof TlsAuthVerifierAdapterConfig tlsAuthVerifierAdapterConfig)) {
                    throw new UnsupportedOperationException(
                            "VerifierAdapterConfig does not match VerifierAdapterType");
                }
                yield TlsServerAuthVerifierAdapter.fromConfig(tlsAuthVerifierAdapterConfig);
            }
            default -> throw new UnsupportedOperationException("Unsupported VerifierAdapterType");
        };
    }
}
