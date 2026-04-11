/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.protocol.crypto.signature.RsaPkcs1SignatureComputations;
import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapterFactory;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

public abstract class SimpleProbe implements Probe {

    public void generateCrl(String outputFile, String cnfPath, String keyPath, String certPath) {

        System.out.println("Generating CRL file: " + outputFile);
        runCommand("openssl", "ca",
                "-config", cnfPath,
                "-gencrl",
                "-keyfile", keyPath,
                "-cert", certPath,
                "-out", outputFile,
                "-crldays", "30",
                "-batch");

        runCommand("openssl", "crl",
                "-in", outputFile,
                "-inform", "PEM",
                "-outform", "DER",
                "-out", outputFile);
        //runCommand("cp", pemPath, "../../crls");
    }

    private void runCommand(String... cmd) {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = null;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String output = null;
        try {
            output = new String(p.getInputStream().readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        int exitCode = 0;
        try {
            exitCode = p.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (exitCode != 0) {
            throw new RuntimeException("Command failed: " + String.join(" ", cmd) + "\n" + output);
        }
    }

    @Override
    public ProbeResult execute() throws ProbeException {
        // dual config initialization here
        X509CertificateChainConfig config = prepareConfig();
        X509CertificateChainGenerator certificateChainGenerator =
                new X509CertificateChainGenerator(config);
        try {
            certificateChainGenerator.generateCertificateChain();
        } catch (CertificateGeneratorException e) {
            throw new ProbeException("Unable to generate certificate from config", e);
        }
        List<X509Certificate> certificateChain =
                certificateChainGenerator.retrieveCertificateChain();
        File RESOURCES_PATH = new File("resources");
        String outPath = RESOURCES_PATH.getAbsolutePath() + "/out/";
        X509CertificateConfig entityConfig = config.getEntityCertificateConfig();
        String serialNumber = String.valueOf(entityConfig.getSerialNumber());
        X509Util.exportCertificates(certificateChain, outPath + serialNumber);
        writeCnf(outPath+"index.txt",outPath+"crlnumber",outPath+"ca.cnf");
        X509Certificate leafCert = certificateChain.getLast();
        RsaPkcs1SignatureComputations leafCertSignatureComputations = (RsaPkcs1SignatureComputations) leafCert.getSignatureComputations();
        generateCRLKeyfileforCertificate(leafCertSignatureComputations.getModulus().getValue(), leafCertSignatureComputations.getPrivateKey().getValue(), certificateChain.size() - 2, serialNumber);
        generateCrl(outPath+"../crls/"+serialNumber+".crl", outPath + "ca.cnf", outPath + serialNumber + "/crl-key.pem", getHighestInterCert(outPath + serialNumber));

        TestConfig testConfig = ContextHelper.getTestConfig();
        VerifierAdapter verifierAdapter =
                VerifierAdapterFactory.getInstance(
                        testConfig.getVerifierAdapterType(), testConfig.getVerifierAdapterConfig());
        try {
            VerifierResult verifierResult =
                    verifierAdapter.invokeVerifier(
                            config.getEntityCertificateConfig(), certificateChain);
            return createResult(verifierResult);
        } catch (VerifierException e) {
            throw new ProbeException("Invoking the verifier for probe failed", e);
        }
    }

    public static String getHighestInterCert(String directory) {
        try {
            return Files.list(Paths.get(directory))
                    .filter(p -> p.getFileName().toString().matches("inter_cert_\\d+\\.pem"))
                    .max(Comparator.comparingInt(p ->
                            Integer.parseInt(p.getFileName().toString().replace("inter_cert_", "").replace(".pem", ""))))
                    .map(Path::toString)
                    .orElseThrow(() -> new RuntimeException("No inter_cert_x.pem found in " + directory));
        } catch (Exception e) {
            return directory+"/root_cert.pem";
        }
    }

    public static void writeCnf(String indexPath, String crlNumberPath, String cnfPath) {
        String cnf = "[ca]\n"
                + "default_ca = CA_default\n\n"
                + "[CA_default]\n"
                + "database        = " + indexPath + "\n"
                + "crlnumber       = " + crlNumberPath + "\n"
                + "default_md      = sha256\n"
                + "default_crl_days = 30\n\n"
                + "[crl_ext]\n"
                + "authorityKeyIdentifier = keyid:always\n";

        try {
            Files.write(Paths.get(cnfPath), cnf.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String generateCRLKeyfileforCertificate(BigInteger modulus, BigInteger privateExponent, int intermediateCertsModeled, String folder) {
        /*
         * After generating the CRL keyfile, you should generate the crl file of the appropriate ca then generate the crl using openssl cli
         * */

        BigInteger publicExponent = BigInteger.valueOf(65537);

        // reconstruct p and q from n, e, d
        // using the standard algorithm from NIST SP 800-56B
        BigInteger k = privateExponent.multiply(publicExponent).subtract(BigInteger.ONE);
        BigInteger p = null, q = null;

        Random rng = new Random();
        outer:
        while (true) {
            BigInteger g = new BigInteger(modulus.bitLength(), rng);
            BigInteger t = k;
            while (!t.testBit(0)) {
                t = t.shiftRight(1);
                BigInteger x = g.modPow(t, modulus);
                if (x.compareTo(BigInteger.ONE) > 0
                        && x.compareTo(modulus.subtract(BigInteger.ONE)) < 0) {
                    BigInteger y = x.multiply(x).mod(modulus);
                    if (y.equals(BigInteger.ONE)) {
                        p = x.subtract(BigInteger.ONE).gcd(modulus);
                        q = modulus.divide(p);
                        break outer;
                    }
                }
            }
        }

        // compute CRT parameters
        BigInteger dp = privateExponent.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = privateExponent.mod(q.subtract(BigInteger.ONE));
        BigInteger qInv = q.modInverse(p);
        RSAPrivateCrtKeySpec spec =
                new RSAPrivateCrtKeySpec(
                        modulus, publicExponent, privateExponent, p, q, dp, dq, qInv);
        PrivateKey privateKey = null;
        try {
            privateKey = KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] encoded = privateKey.getEncoded();
        System.out.println("\n\n========="+"Creating Private Key file for CRL:\n Modulus is: " + modulus + "\nprivate exponent is: " + privateExponent + "\nfolder is: " + folder);
        String pem =
                "-----BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded)
                        + "\n-----END PRIVATE KEY-----\n";
        File RESOURCES_PATH = new File("resources");
        try (FileWriter fw =
                     new FileWriter(
                             RESOURCES_PATH.getAbsolutePath()
                                     + "/out/" + folder + "/crl-key.pem")) {
            fw.write(pem);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
        return pem;

    }

    protected abstract X509CertificateChainConfig prepareConfig();

    protected abstract ProbeResult createResult(VerifierResult verifierResult);
}


