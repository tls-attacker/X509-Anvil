package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.X509Certificate;

public class NopX509CertificateModifier implements X509CertificateModifier {
    @Override
    public void beforeSigning(X509Certificate certificate, X509CertificateConfig config, X509CertificateConfig previousConfig) {}
}