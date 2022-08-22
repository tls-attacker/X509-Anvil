package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
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

    public static X509CertificateModifier invalidExtensionValueModifier(boolean entity, String extensionOid) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Sequence extension = X509Util.getExtensionByOid(certificate, extensionOid);
                Asn1PrimitiveOctetString extnValue;
                if (extension.getChildren().get(1) instanceof Asn1PrimitiveOctetString) {
                    extnValue = (Asn1PrimitiveOctetString) extension.getChildren().get(1);
                }
                else if (extension.getChildren().get(2) instanceof Asn1PrimitiveOctetString) {
                    extnValue = (Asn1PrimitiveOctetString) extension.getChildren().get(2);
                }
                else {
                    throw new RuntimeException("Extension has no value");
                }

                extnValue.setValue(new byte[]{0x01,0x01,(byte) 0xFF});
            }
        };
    }

    public static X509CertificateModifier duplicateIdenticalExtensionModifier(boolean entity, String extensionOid) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Sequence extensionSequence = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "explicitExtensions", "extensions");
                Asn1Sequence extension = null;
                try {
                    extension = (Asn1Sequence) X509Util.getExtensionByOid(certificate, extensionOid).getCopy();
                } catch (JAXBException | IOException | XMLStreamException e) {
                    throw new RuntimeException(e);
                }
                extension.setIdentifier(extension.getIdentifier() + "_copy");
                extensionSequence.addChild(extension);
            }
        };
    }

    public static X509CertificateModifier duplicateDifferentExtensionModifier(boolean entity, String extensionOid, byte[] extensionValue) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Sequence extensionSequence = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "explicitExtensions", "extensions");
                Asn1Sequence extension = null;
                try {
                    extension = (Asn1Sequence) X509Util.getExtensionByOid(certificate, extensionOid).getCopy();
                } catch (JAXBException | IOException | XMLStreamException e) {
                    throw new RuntimeException(e);
                }
                extension.setIdentifier(extension.getIdentifier() + "_copy");

                Asn1PrimitiveOctetString extnValue;
                if (extension.getChildren().get(1) instanceof Asn1PrimitiveOctetString) {
                    extnValue = (Asn1PrimitiveOctetString) extension.getChildren().get(1);
                }
                else if (extension.getChildren().get(2) instanceof Asn1PrimitiveOctetString) {
                    extnValue = (Asn1PrimitiveOctetString) extension.getChildren().get(2);
                }
                else {
                    throw new RuntimeException("Extension has no value");
                }
                extnValue.setValue(extensionValue);

                extensionSequence.addChild(extension);
            }
        };
    }
}
