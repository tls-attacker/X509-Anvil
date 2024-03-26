package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;

import de.rub.nds.x509attacker.x509.model.Extension;
import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

public class Modifiers {

    public static X509CertificateModifier removeFieldModifier(boolean entity, String... path) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Encodable field = X509Util.getAsn1ElementByIdentifierPath(certificate, path);
                String[] parentPath = Arrays.copyOf(path, path.length-1);
                Asn1Container parent = (Asn1Container) X509Util.getAsn1ElementByIdentifierPath(certificate, parentPath);
                parent.getChildren().remove(field);
            }
        };
    }

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
                Extension extension = X509Util.getExtensionByOid(certificate, extensionOid);
                Asn1OctetString extnValue = extension.getExtnValue();

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
                extension = X509Util.getExtensionByOid(certificate, extensionOid);

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
                extension = (Asn1Sequence) X509Util.getExtensionByOid(certificate, extensionOid);

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

    public static X509CertificateModifier nameComponentMismatchModifier(String oid) {
        return (certificate, config, previousConfig) -> {
            if (config.isEntity()) {
                Asn1Sequence subjectAsn1 = (Asn1Sequence) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "issuer");
                Asn1Sequence attribute = X509Util.getAttributeFromName(subjectAsn1, oid);
                if (attribute.getChildren().get(1) instanceof Asn1PrimitivePrintableString) {
                    Asn1PrimitivePrintableString value = (Asn1PrimitivePrintableString) attribute.getChildren().get(1);
                    value.setValue(value.getValue() + "_modified");
                }
                else if (attribute.getChildren().get(1) instanceof Asn1PrimitiveUtf8String) {
                    Asn1PrimitiveUtf8String value = (Asn1PrimitiveUtf8String) attribute.getChildren().get(1);
                    value.setValue(value.getValue() + "_modified");
                }
                else {
                    throw new RuntimeException("Could not change name component with oid " + oid);
                }
            }
        };
    }
}
