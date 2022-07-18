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
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
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
                        .orElseThrow(() -> new IllegalArgumentException("Could not find " + identifier + " in " + String.join(".", identifiers)));
            }
            else {
                throw new IllegalArgumentException(identifier + " is not a container");
            }
        }
        return currentAsn1Encodable;
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
}
