package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;

import java.math.BigInteger;

public class Modifiers {
    public static X509CertificateModifier illegalVersionModifier(boolean entity, BigInteger version) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Integer versionAsn1 = (Asn1Integer) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "explicitversion", "version");
                versionAsn1.setValue(version);
            }
        };
    }

    public static X509CertificateModifier illegalSerialNumberModifier(boolean entity, BigInteger version) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Integer serialNumberAsn1 = (Asn1Integer) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "serialNumber");
                serialNumberAsn1.setValue(version);
            }
        };
    }

    public static X509CertificateModifier tbsSignatureMismatchModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1ObjectIdentifier tbsSignatureAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "signature", "algorithm");
                tbsSignatureAsn1.setValue(TestUtils.getNonMatchingAlgorithmOid(previousConfig.getSignatureAlgorithm()));
            }
        };
    }

    public static X509CertificateModifier tbsSignatureUnknownOidModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1ObjectIdentifier tbsSignatureAsn1 = (Asn1ObjectIdentifier) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "signature", "algorithm");
                tbsSignatureAsn1.setValue("1.2.3.4.5.6.7.8");
            }
        };
    }
}
