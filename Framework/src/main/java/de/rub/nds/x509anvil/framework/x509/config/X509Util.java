/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.protocol.crypto.key.PrivateKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.*;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

// TODO: what is even needed anymore?
public class X509Util {
    public static Extension getExtensionByOid(X509Certificate x509Certificate, String oid) {
        try {
            return x509Certificate.getTbsCertificate().getExplicitExtensions().getInnerField().getExtensionList()
                .stream().filter(extension -> extension.getExtnID().getValue().getValue().equals(oid))
                .collect(Collectors.toList()).get(0);
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Extensions not found");
        }
    }

    static PrivateKeyContainer containerFromPrivateKey(PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateKey castedKey = (RSAPrivateKey) privateKey;
            return new RsaPrivateKey(castedKey.getPrivateExponent(), castedKey.getModulus());
        } else {
            throw new UnsupportedOperationException(
                "Private keys of type " + privateKey.getAlgorithm() + " not supported yet. Only RSA supported.");
        }
    }

    public static X509RsaPublicKey containerFromPublicKey(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey castedKey = (RSAPublicKey) publicKey;
            X509RsaPublicKey x509RsaPublicKey = new X509RsaPublicKey("publicKey");

            Asn1Integer exponent = new Asn1Integer("exponent");
            exponent.setValue(castedKey.getPublicExponent());
            x509RsaPublicKey.setPublicExponent(exponent);

            Asn1Integer modulus = new Asn1Integer("modulus");
            modulus.setValue(castedKey.getModulus());
            x509RsaPublicKey.setModulus(modulus);
            return x509RsaPublicKey;
        } else {
            throw new UnsupportedOperationException(
                "Private keys of type " + publicKey.getAlgorithm() + " not supported yet. Only RSA supported.");
        }
    }

    public static void exportCertificates(List<X509Certificate> certificateChain, String directory) {
        X509CertificateChain x509CertificateChain = new X509CertificateChain(certificateChain);
        if (x509CertificateChain.size() >= 1) {
            writeCertificate(directory, "root_cert", x509CertificateChain.getCertificateList().get(0));
        }
        if (x509CertificateChain.size() >= 2) {
            writeCertificate(directory, "leaf_cert",
                x509CertificateChain.getCertificateList().get(x509CertificateChain.size() - 1));
        }
        if (x509CertificateChain.size() >= 3) {
            x509CertificateChain.getCertificateList().subList(1, x509CertificateChain.size() - 1)
                .forEach(x -> writeCertificate(directory, "inter_cert_" + (certificateChain.indexOf(x) - 1), x));
        }
    }

    private static void writeCertificate(String directory, String filename, X509Certificate certificate) {
        try {
            String certificateFileName = filename + ".pem";
            CertificateFileWriter certificateFileWriter =
                new CertificateFileWriter(new File(directory + "/" + certificateFileName));
            certificateFileWriter.writeCertificate(certificate.getContent().getValue());
            certificateFileWriter.close();
        } catch (IOException e) {
            throw new RuntimeException("Error writing Certificate to PEM: " + e);
        }
    }

    public static RelativeDistinguishedName getCnFromName(Name name) {
        return getRdnFromName(name, AttributeTypeObjectIdentifiers.COMMON_NAME);
    }

    public static RelativeDistinguishedName getRdnFromName(Name name, String oid) {
        for (RelativeDistinguishedName relativeDistinguishedName : name.getRelativeDistinguishedNames()) {
            if (relativeDistinguishedName.getAttributeTypeAndValueList().stream().anyMatch(
                attributeTypeAndValue -> Objects.equals(attributeTypeAndValue.getType().getValue().getValue(), oid))) {
                return relativeDistinguishedName;
            }
        }
        return null;
    }

    public static void addDnQualifierToName(Name name) {
        RelativeDistinguishedName newRdn = new RelativeDistinguishedName("new_dnq");
        AttributeTypeAndValue attributeTypeAndValue = new AttributeTypeAndValue("dnq", DirectoryStringChoiceType.PRINTABLE_STRING);
        Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier("dnq");
        asn1ObjectIdentifier.setValue(AttributeTypeObjectIdentifiers.DN_QUALIFIER);
        attributeTypeAndValue.setType(asn1ObjectIdentifier);
        newRdn.addAttributeTypeAndValue(attributeTypeAndValue);
        name.addRelativeDistinguishedNames(newRdn);
    }
}
