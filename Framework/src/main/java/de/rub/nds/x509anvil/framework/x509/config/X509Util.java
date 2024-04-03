/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.*;

import javax.security.cert.CertificateException;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

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

    public static KeyPair retrieveKeyPairFromX509Certificate(X509Certificate x509Certificate) {
        try {
            PrivateKey privateKey = retrievePrivateKeyFromCertificate(x509Certificate);
            PublicKey publicKey = retrievePublicKeyFromSubjectPublicKeyInfo(x509Certificate);
            return new KeyPair(publicKey, privateKey);
        } catch (CertificateException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Unable to retrieve key pair from x509Certificate", e);
        }
    }

    public static PrivateKey retrievePrivateKeyFromCertificate(X509Certificate x509Certificate)
        throws InvalidKeySpecException {
        byte[] privateKeyBytes = x509Certificate.getContent().getValue();

        KeyFactory keyFactory;
        try {
            switch (x509Certificate.getPublicKey().getX509PublicKeyType()) {
                case RSA:
                    keyFactory = KeyFactory.getInstance("RSA");
                    break;
                case DSA:
                    keyFactory = KeyFactory.getInstance("DSA");
                    break;
                case ECDH_ECDSA:
                    keyFactory = KeyFactory.getInstance("EC");
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "No key factory for key type " + x509Certificate.getPublicKey().getX509PublicKeyType().name());
        }

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public static PublicKey retrievePublicKeyFromSubjectPublicKeyInfo(X509Certificate x509Certificate)
        throws CertificateException {
        // TODO: This is a workaround because using the Asn1-Tool classes didn't work
        byte[] certBytes = x509Certificate.getContent().getValue();
        javax.security.cert.X509Certificate cert = javax.security.cert.X509Certificate.getInstance(certBytes);
        return cert.getPublicKey();
    }

    private static void writeUint24(int value, OutputStream outputStream) throws IOException {
        if ((value & 16777215) != value) {
            throw new IOException("Certificate chain too large for 24 bit length field");
        }

        outputStream.write((byte) (value >>> 16));
        outputStream.write((byte) (value >>> 8));
        outputStream.write((byte) value);
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
        AttributeTypeAndValue attributeTypeAndValue = new AttributeTypeAndValue("dnq");
        Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier("dnq");
        asn1ObjectIdentifier.setValue(AttributeTypeObjectIdentifiers.DN_QUALIFIER);
        attributeTypeAndValue.setType(asn1ObjectIdentifier);
        newRdn.addAttributeTypeAndValue(attributeTypeAndValue);
        name.addRelativeDistinguishedNames(newRdn);
    }
}
