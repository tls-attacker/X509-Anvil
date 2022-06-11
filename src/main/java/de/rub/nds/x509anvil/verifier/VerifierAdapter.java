package de.rub.nds.x509anvil.verifier;

import de.rub.nds.x509anvil.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.util.List;

public interface VerifierAdapter {
    VerifierResult invokeVerifier(List<X509Certificate> certificatesChain, X509CertificateChainConfig chainConfig) throws VerifierException;
}
