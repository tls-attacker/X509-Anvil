package de.rub.nds.x509anvil.framework.verifier.adapter.util;

import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Objects;

public class PkcsUtil {

    protected static final Logger LOGGER = LogManager.getLogger();

    public static void execNSSPkcs12Setup() {
        if (!isPk12utilCommandAvailable()) {
            throw new RuntimeException("Missing libnss3-tools! Please install it before continuing.");
        }

        try {
            ProcessBuilder builder = new ProcessBuilder("bash", X509Util.RESOURCES_PATH.getAbsolutePath()+ "/setup_nssdb.sh");
            builder.redirectErrorStream(true);

            Process process = builder.start();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("NSS setup script failed with exit code: " + exitCode);
            }
        }catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public static void convertPkcs1toPkcs8PrivateKey() {
        try {
            Path in = Path.of(X509Util.RESOURCES_PATH.getAbsolutePath(), "static-root/private-key.pem");
            Path out = Path.of(X509Util.RESOURCES_PATH.getAbsolutePath(), "static-root/private-key-pkcs8.pem");
try (BufferedReader reader = Files.newBufferedReader(in, StandardCharsets.US_ASCII);
     PEMParser pemParser = new PEMParser(reader);
     BufferedWriter bw = Files.newBufferedWriter(out, StandardCharsets.US_ASCII);
     JcaPEMWriter pemWriter = new JcaPEMWriter(bw)) {

            Object obj = pemParser.readObject();
            if (obj == null) {
                throw new IllegalArgumentException("No PEM object found in file: " + in);
            }

            PrivateKey privateKey;

            if (obj instanceof PrivateKeyInfo) {
                // Already PKCS#8 — write it back out as PKCS#8
                pemWriter.writeObject(obj);
                return;
            } else if (obj instanceof PEMKeyPair) {
                // Some "RSA PRIVATE KEY" files parse as a PEMKeyPair; extract the private part
                privateKey = new JcaPEMKeyConverter().setProvider("BC")
                        .getKeyPair((PEMKeyPair) obj).getPrivate();
            } else if (obj instanceof RSAPrivateKey rsa) {
                // Typical PKCS#1 case
                RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(
                        rsa.getModulus(),
                        rsa.getPublicExponent(),
                        rsa.getPrivateExponent(),
                        rsa.getPrime1(),
                        rsa.getPrime2(),
                        rsa.getExponent1(),
                        rsa.getExponent2(),
                        rsa.getCoefficient()
                );
                privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
            } else {
                throw new IllegalArgumentException("Unsupported key type in PEM: " + obj.getClass().getName());
            }

            // Emit PKCS#8 PEM ("BEGIN PRIVATE KEY")
            PemObject pkcs8 = new JcaPKCS8Generator(privateKey, null).generate();
            pemWriter.writeObject(pkcs8);
        }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Unable to convert PKCS1 to PKCS8 Private Key", e);
        }
    }

    private static boolean isPk12utilCommandAvailable() {
        try {
            Process process = new ProcessBuilder("which", "pk12util").start();
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
