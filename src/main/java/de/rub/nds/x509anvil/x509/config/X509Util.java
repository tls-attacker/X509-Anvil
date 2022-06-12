package de.rub.nds.x509anvil.x509.config;

import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class X509Util {
    public static byte[] encodeCertificateChainForTls(List<X509Certificate> certificates) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        List<byte[]> encodedCertificates = new ArrayList<>();
        int lengthField = 0;

        for (int i = certificates.size()-1; i >= 0; i--) {
            X509Certificate certificate = certificates.get(i);
            byte[] encodedCertificate = certificate.getEncodedCertificate();
            lengthField += encodedCertificate.length + 3;   // 24 bit length field
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

        outputStream.write((byte)(value >>> 16));
        outputStream.write((byte)(value >>> 8));
        outputStream.write((byte)value);
    }

    public static void exportCertificates(List<X509Certificate> certificateChain, String directory) {
        X509CertificateChain x509CertificateChain = new X509CertificateChain(certificateChain);
        x509CertificateChain.writeCertificateChainToFile(directory, X509CertChainOutFormat.CHAIN_ALL_IND_ROOT_TO_LEAF);
    }
}
