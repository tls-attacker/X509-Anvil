package de.rub.nds.x509anvil.framework.verifier;

public class VerifierAdapterFactory {
    public static VerifierAdapter getInstance(VerifierAdapterType verifierAdapterType, VerifierAdapterConfig verifierAdapterConfig) {
        switch (verifierAdapterType) {
            case TLS_CLIENT_AUTH:
                if (!(verifierAdapterConfig instanceof TlsClientAuthVerifierAdapterConfig)) {
                    throw new UnsupportedOperationException("VerifierAdapterConfig does not match VerifierAdapterType");
                }
                TlsClientAuthVerifierAdapterConfig tlsClientAuthVerifierAdapterConfig = (TlsClientAuthVerifierAdapterConfig) verifierAdapterConfig;
                return TlsClientAuthVerifierAdapter.fromConfig(tlsClientAuthVerifierAdapterConfig);

            default:
                throw new UnsupportedOperationException("Unsupported VerifierAdapterType");
        }
    }
}
