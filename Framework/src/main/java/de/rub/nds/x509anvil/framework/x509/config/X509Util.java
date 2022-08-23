/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.x509anvil.framework.util.PemUtil;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.model.DirectoryStringType;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;

import javax.security.cert.CertificateException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class X509Util {
    public static Asn1Encodable getAsn1ElementByIdentifierPath(X509Certificate x509Certificate, String... identifiers) {
        Asn1Encodable currentAsn1Encodable = x509Certificate.getCertificate();

        for (String identifier : identifiers) {
            if (currentAsn1Encodable instanceof Asn1Container) {
                currentAsn1Encodable = ((Asn1Container) currentAsn1Encodable).getChildren().stream()
                        .filter(encodable -> encodable.getIdentifier().equals(identifier))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Could not find " + identifier + " in " + String.join("/", identifiers)));
            }
            else {
                throw new IllegalArgumentException(identifier + " is not a container");
            }
        }
        return currentAsn1Encodable;
    }

    public static Asn1Encodable getAsn1ElementByIdentifierPath(Asn1Container asn1Container, String... identifiers) {
        Asn1Encodable currentAsn1Encodable = asn1Container;
        for (String identifier : identifiers) {
            if (currentAsn1Encodable instanceof Asn1Container) {
                currentAsn1Encodable = ((Asn1Container) currentAsn1Encodable).getChildren().stream()
                        .filter(encodable -> encodable.getIdentifier().equals(identifier))
                        .findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Could not find " + identifier + " in " + String.join("/", identifiers)));
            }
            else {
                throw new IllegalArgumentException(identifier + " is not a container");
            }
        }
        return currentAsn1Encodable;
    }

    public static Asn1Sequence getExtensionByOid(X509Certificate x509Certificate, String oid) {
        Asn1Sequence extensionsAsn1 = (Asn1Sequence) getAsn1ElementByIdentifierPath(x509Certificate,
                "tbsCertificate", "explicitExtensions", "extensions");
        for (Asn1Encodable child : extensionsAsn1.getChildren()) {
            if (!(child instanceof Asn1Sequence)) {
                throw new IllegalArgumentException("Unexpected Asn1 Tag while searching for extension");
            }
            Asn1Sequence extension = (Asn1Sequence) child;
            if (extension.getChildren().get(0) instanceof Asn1ObjectIdentifier) {
                Asn1ObjectIdentifier extnId = (Asn1ObjectIdentifier) extension.getChildren().get(0);
                if (extnId.getValue().equals(oid)) {
                    return extension;
                }
            }
        }
        throw new IllegalArgumentException("Extensions not found");
    }

    public static KeyPair retrieveKeyPairFromX509Certificate(X509Certificate x509Certificate) {
        try {
            PrivateKey privateKey = retrievePrivateKeyFromKeyInfo(x509Certificate.getKeyInfo());
            PublicKey publicKey = retrievePublicKeyFromSubjectPublicKeyInfo(x509Certificate, privateKey.getAlgorithm());
            return new KeyPair(publicKey, privateKey);
        } catch (CertificateException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("Unable to retrieve key pair from x509Certificate", e);
        }
    }

    public static PrivateKey retrievePrivateKeyFromKeyInfo(KeyInfo privateKeyInfo) throws InvalidKeySpecException {
        byte[] privateKeyBytes = PemUtil.pemToDer(privateKeyInfo.getKeyBytes());

        KeyFactory keyFactory;
        try {
            switch (privateKeyInfo.getKeyType()) {
                case RSA:
                    keyFactory = KeyFactory.getInstance("RSA");
                    break;
                case DSA:
                    keyFactory = KeyFactory.getInstance("DSA");
                    break;
                case ECDSA:
                    keyFactory = KeyFactory.getInstance("EC");
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported key type");
            }
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No key factory for key type " + privateKeyInfo.getKeyType().name());
        }

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public static PublicKey retrievePublicKeyFromSubjectPublicKeyInfo(X509Certificate x509Certificate, String algorithm) throws CertificateException {
        // TODO: This is a workaround because using the Asn1-Tool classes didn't work
        byte[] certBytes = x509Certificate.getEncodedCertificate();
        javax.security.cert.X509Certificate cert = javax.security.cert.X509Certificate.getInstance(certBytes);
        return cert.getPublicKey();
    }

    public static byte[] encodeCertificateChainForTls(List<X509Certificate> certificates) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        List<byte[]> encodedCertificates = new ArrayList<>();
        int lengthField = 0;

        for (int i = certificates.size() - 1; i >= 0; i--) {
            X509Certificate certificate = certificates.get(i);
            byte[] encodedCertificate = certificate.getEncodedCertificate();
            lengthField += encodedCertificate.length + 3; // 24 bit length field
            encodedCertificates.add(encodedCertificate);
        }

        // Encode length field for entire chain
        writeUint24(lengthField, byteArrayOutputStream);

        for (byte[] encodedCertificate : encodedCertificates) {
            // Encode length field for single certificate
            writeUint24(encodedCertificate.length, byteArrayOutputStream);
            // Write encoded certificate
            byteArrayOutputStream.write(encodedCertificate);
        }

        return byteArrayOutputStream.toByteArray();
    }

    private static void writeUint24(int value, OutputStream outputStream) throws IOException {
        if ((value & 16777215) != value) {
            throw new IOException("Certificate chain too large for 24 bit length field");
        }

        outputStream.write((byte) (value >>> 16));
        outputStream.write((byte) (value >>> 8));
        outputStream.write((byte) value);
    }

    public static byte[] extractKeyBytesFromSubjectPublicKeyInfo(byte[] subjectPublicKeyInfoBytes) {
        Asn1Parser asn1Parser = new Asn1Parser(subjectPublicKeyInfoBytes, false);
        List<IntermediateAsn1Field> intermediateAsn1Fields = asn1Parser.parseIntermediateFields();
        // TODO Error handling
        return intermediateAsn1Fields.get(0).getChildren().get(1).getContent();
    }

    public static void exportCertificates(List<X509Certificate> certificateChain, String directory) {
        X509CertificateChain x509CertificateChain = new X509CertificateChain(certificateChain);
        x509CertificateChain.writeCertificateChainToFile(directory, X509CertChainOutFormat.CHAIN_ALL_IND_ROOT_TO_LEAF);
    }

    public static Asn1PrimitivePrintableString getCnFromName(Asn1Sequence name) {
        for (Asn1Encodable child : name.getChildren()) {
            if (child instanceof Asn1Set) {
                Asn1Set relativeDistinguishedName = (Asn1Set) child;
                for (Asn1Encodable rdnchild : relativeDistinguishedName.getChildren()) {
                    if (rdnchild instanceof Asn1Sequence) {
                        Asn1Sequence attributeTypeAndValue = (Asn1Sequence) rdnchild;
                        Asn1Encodable objectId = attributeTypeAndValue.getChildren().get(0);
                        if (objectId instanceof Asn1ObjectIdentifier) {
                            if (((Asn1ObjectIdentifier) objectId).getValue().equals(AttributeTypeObjectIdentifiers.COMMON_NAME)) {
                                if (attributeTypeAndValue.getChildren().get(1) instanceof Asn1PrimitivePrintableString) {
                                    return (Asn1PrimitivePrintableString) attributeTypeAndValue.getChildren().get(1);
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public static Asn1Set getRdnFromName(Asn1Sequence name, String oid) {
        for (Asn1Encodable child : name.getChildren()) {
            if (child instanceof Asn1Set) {
                Asn1Set relativeDistinguishedName = (Asn1Set) child;
                for (Asn1Encodable rdnchild : relativeDistinguishedName.getChildren()) {
                    if (rdnchild instanceof Asn1Sequence) {
                        Asn1Sequence attributeTypeAndValue = (Asn1Sequence) rdnchild;
                        Asn1Encodable objectId = attributeTypeAndValue.getChildren().get(0);
                        if (objectId instanceof Asn1ObjectIdentifier) {
                            if (((Asn1ObjectIdentifier) objectId).getValue().equals(oid)) {
                                return relativeDistinguishedName;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public static Asn1Encodable getDirectoryString(String value, DirectoryStringType type) {
        switch (type) {
            case PRINTABLE:
                Asn1PrimitivePrintableString primitivePrintableString = new Asn1PrimitivePrintableString();
                primitivePrintableString.setValue(value);
                return primitivePrintableString;
            case UTF8:
            default:
                Asn1PrimitiveUtf8String utf8String = new Asn1PrimitiveUtf8String();
                utf8String.setValue(value);
                return utf8String;
        }
    }
}
