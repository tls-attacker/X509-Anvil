/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import javax.security.cert.CertificateException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
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
        x509CertificateChain.writeCertificateChainToFile(directory, X509CertChainOutFormat.CHAIN_ALL_IND_ROOT_TO_LEAF);
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
}
