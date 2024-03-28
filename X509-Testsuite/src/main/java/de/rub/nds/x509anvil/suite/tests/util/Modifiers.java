package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.asn1.model.*;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;

import de.rub.nds.x509attacker.constants.TimeContextHint;
import de.rub.nds.x509attacker.x509.model.*;

import java.math.BigInteger;
import java.util.Arrays;

public class Modifiers {

    public static X509CertificateModifier illegalVersionModifier(boolean entity, BigInteger version) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                certificate.getTbsCertificate().getVersion().getInnerField().setValue(version);
            }
        };
    }

    public static X509CertificateModifier illegalSerialNumberModifier(boolean entity, BigInteger version) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                certificate.getTbsCertificate().getSerialNumber().setValue(version);
            }
        };
    }

    public static X509CertificateModifier tbsSignatureMismatchModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                certificate.getTbsCertificate().getSignature().getAlgorithm().setValue(TestUtils.getNonMatchingAlgorithmOid(previousConfig.getSignatureAlgorithm()));
            }
        };
    }

    public static X509CertificateModifier tbsSignatureUnknownOidModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                certificate.getTbsCertificate().getSignature().getAlgorithm().setValue("1.2.3.4.5.6.7.8");
            }
        };
    }

    public static X509CertificateModifier invalidExtensionValueModifier(boolean entity, String extensionOid) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, extensionOid);
                Asn1OctetString extnValue = extension.getExtnValue();

                extnValue.setValue(new byte[]{0x01, 0x01, (byte) 0xFF});
            }
        };
    }

    public static X509CertificateModifier duplicateIdenticalExtensionModifier(boolean entity, String extensionOid) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, extensionOid);
                extension.setIdentifier(extension.getIdentifier() + "_copy");
                certificate.getTbsCertificate().getExplicitExtensions().getInnerField().getExtensionList().add(extension);
            }
        };
    }

    public static X509CertificateModifier duplicateDifferentExtensionModifier(boolean entity, String extensionOid, byte[] extensionValue) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, extensionOid);

                extension.setIdentifier(extension.getIdentifier() + "_copy");
                Asn1OctetString asn1OctetString = new Asn1OctetString("copied");
                asn1OctetString.setValue(extensionValue);
                extension.setExtnValue(asn1OctetString);

                certificate.getTbsCertificate().getExplicitExtensions().getInnerField().getExtensionList().add(extension);
            }
        };

    }

    public static X509CertificateModifier nameComponentMismatchModifier(String oid) {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Name issuer = certificate.getTbsCertificate().getIssuer();
                RelativeDistinguishedName rdn = X509Util.getRdnFromName(issuer, oid);
                Asn1PrintableString asn1PrintableString = (Asn1PrintableString) rdn.getAttributeTypeAndValueList().get(0).getValue();
                asn1PrintableString.setValue(asn1PrintableString.getValue().getValue() + "_modified");
            }
        };
    }

    public static X509CertificateModifier removeValidityModifier(boolean entity, boolean removeNotAfter, boolean removeNotBefore) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                if (removeNotAfter) {
                    certificate.getTbsCertificate().getValidity().setNotAfter(new Time("empty", TimeContextHint.NOT_AFTER));
                } else if (removeNotBefore) {
                    certificate.getTbsCertificate().getValidity().setNotBefore(new Time("empty", TimeContextHint.NOT_BEFORE));
                } else {
                    Validity validity = new Validity("empty");
                    certificate.getTbsCertificate().setValidity(validity);
                }
            }
        };
    }
}
