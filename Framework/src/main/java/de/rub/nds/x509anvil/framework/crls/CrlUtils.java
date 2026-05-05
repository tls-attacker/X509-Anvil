package de.rub.nds.x509anvil.framework.crls;

import de.rub.nds.protocol.crypto.signature.RsaPkcs1SignatureComputations;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509attacker.config.CrlConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

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
import java.util.*;

public class CrlUtils {
    private static final String outPath = new File("resources").getAbsolutePath() + "/out/";
    private static final Object CRL_LOCK = new Object();

    public static String getUniqueID() {
        return System.currentTimeMillis() + "_" + UUID.randomUUID();
    }

    public static void GenerateCRLs(X509CertificateConfig entityConfig, List<X509Certificate> certificateChain) {
        String uniqueIDToUse = entityConfig.getCrlUniqueID();
        for (int i = 0; i < entityConfig.getCrlConfigs().size(); i++) {
            CrlConfig crlConfig = entityConfig.getCrlConfigs().get(i);
            uniqueIDToUse = uniqueIDToUse+crlConfig.getCrlNameSuffix();
            System.out.println("Generating CRLs for " + uniqueIDToUse);
            X509Util.exportCertificates(certificateChain, outPath + "certs_for_crls/" + uniqueIDToUse);
            IdpConfig idpConfig = new IdpConfig();
            if (crlConfig.getOnlySomeReasons() == null) {
                idpConfig = null;
            } else {
                idpConfig.onlySomeReasons = crlConfig.getOnlySomeReasons();
            }
            writeCnf(outPath + "index.txt", outPath + "crlnumber", outPath + "ca.cnf", idpConfig, uniqueIDToUse);
            X509Certificate leafCert = certificateChain.getLast();
            RsaPkcs1SignatureComputations leafCertSignatureComputations = (RsaPkcs1SignatureComputations) leafCert.getSignatureComputations();
            generateCRLKeyfile(leafCertSignatureComputations.getModulus().getValue(), leafCertSignatureComputations.getPrivateKey().getValue(), uniqueIDToUse);
            generateCrl(outPath + "../crls/" + uniqueIDToUse + ".crl", outPath + "ca.cnf", outPath + "certs_for_crls/" + uniqueIDToUse + "/crl-key.pem", getHighestInterCert(outPath + "certs_for_crls/" + uniqueIDToUse),crlConfig.isPemInsteadOfDer());
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
            return directory + "/root_cert.pem";
        }
    }

    private static void generateCrl(String outputFile, String cnfPath, String keyPath, String certPath, boolean pemInsteadOfDer) {
        synchronized (CrlUtils.CRL_LOCK) {
            runCommand("openssl", "ca",
                    "-config", cnfPath,
                    "-gencrl",
                    "-keyfile", keyPath,
                    "-cert", certPath,
                    "-out", outputFile,
                    "-crldays", "30",
                    "-batch");

            if(!pemInsteadOfDer){
                runCommand("openssl", "crl",
                        "-in", outputFile,
                        "-inform", "PEM",
                        "-outform", "DER",
                        "-out", outputFile);
            }
        }
    }

    private static void runCommand(String... cmd) {
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


    public static void writeCnf(String indexPath, String crlNumberPath, String cnfPath, IdpConfig idp, String uniqueIDToUse) {
        StringBuilder cnf = new StringBuilder();
        cnf.append("[ca]\n")
                .append("default_ca = CA_default\n\n")
                .append("[CA_default]\n")
                .append("database = ").append(indexPath).append("\n")
                .append("crlnumber = ").append(crlNumberPath).append("\n")
                .append("default_md = sha256\n")
                .append("default_crl_days = 30\n")
                .append("crl_extensions = crl_ext\n\n")
                .append("[crl_ext]\n")
                .append("authorityKeyIdentifier = keyid:always\n");

        if (idp != null) {
            cnf.append("issuingDistributionPoint = ")
                    .append("critical, ")
                    .append("@idp_section\n\n");

            cnf.append("[idp_section]\n");
            //cnf.append("fullname = URI:http://172.17.0.1:8099/crls/").append(uniqueIDToUse).append(".crl\n");
            if (idp.onlySomeReasons != null) {
                cnf.append("onlysomereasons = ").append(String.join(", ", idp.onlySomeReasons)).append("\n");
            }
        }

        try {
            Files.write(Paths.get(cnfPath), cnf.toString().getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    public static void generateCRLKeyfile(BigInteger modulus, BigInteger privateExponent, String folder) {

        /*
         * Source: https://di-mgt.com.au/rsa_factorize_n.html
         * Input: N, e, d.
         * Output: p and q where pq=N.
         *
         * [Initialize] Set k←de−1.
         * [Try a random g] Choose g at random from {2,…,N−1} and set t←k.
         * [Next t] If t is divisible by 2, set t←t/2 and x←g^t mod N. Otherwise go to step 2.
         * [Finished?] If x>1 and y=gcd(x−1,N)>1 then set p←y and q←N/y, output (p,q) and terminate the algorithm. Otherwise go to step 3.
         * */
        BigInteger publicExponent = BigInteger.valueOf(65537);

        BigInteger k = privateExponent.multiply(publicExponent).subtract(BigInteger.ONE);
        BigInteger p = null, q = null;
        Random rng = new Random();
        BigInteger g;

        outer:
        while (true) {
            do {
                g = new BigInteger(modulus.bitLength(), rng);
            } while (g.compareTo(BigInteger.valueOf(2)) < 0 || g.compareTo(modulus) >= 0);
            BigInteger t = k;
            while (!t.testBit(0)) {
                t = t.shiftRight(1);
                BigInteger x = g.modPow(t, modulus);
                if (x.compareTo(BigInteger.ONE) > 0) {
                    BigInteger y = x.subtract(BigInteger.ONE).gcd(modulus);
                    if (y.compareTo(BigInteger.ONE) > 0) {
                        p = y;
                        q = modulus.divide(p);
                        break outer;
                    }
                }
            }
        }

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
        //System.out.println("\n\n=========\n" + "Creating Private Key file for CRL:\nModulus is: " + modulus + "\nprivate exponent is: " + privateExponent + "\nfolder is: " + folder);
        String pem =
                "-----BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded)
                        + "\n-----END PRIVATE KEY-----\n";
        File RESOURCES_PATH = new File("resources");
        try (FileWriter fw =
                     new FileWriter(
                             RESOURCES_PATH.getAbsolutePath()
                                     + "/out/certs_for_crls/" + folder + "/crl-key.pem")) {
            fw.write(pem);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void clean() {
        emptyDirectory(outPath + "../crls/");
        emptyDirectory(outPath + "certs_for_crls/");
    }

    private static void emptyDirectory(String directory) {
        try {
            Files.walk(Paths.get(directory))
                    .sorted(Comparator.reverseOrder())
                    .filter(p -> !p.equals(Paths.get(directory)))
                    .forEach(p -> {
                        try {
                            if (!p.endsWith("upb.crl")) { //Don't delete upb crls
                                Files.delete(p);
                            }
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to delete " + p, e);
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class IdpConfig {
        public String fullName;
        public Set<String> onlySomeReasons;
        public Boolean onlyUser;
        public Boolean onlyCA;
        public Boolean onlyAA;
        public Boolean indirectCRL;
        public boolean critical = true;
    }
}
