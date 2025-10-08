package de.rub.nds.x509anvil.framework.verifier.adapter.util;

import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Paths;

public class NSSPkcs12Util {

    protected static final Logger LOGGER = LogManager.getLogger();

    public static void execSetup() {
        try {
            ProcessBuilder builder = new ProcessBuilder("bash", "X509-Testsuite/resources/setup_nssdb.sh");
            builder.redirectErrorStream(true);

            Process process = builder.start();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println(line);
                }
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new RuntimeException("NSS setup script failed with exit code: " + exitCode);
            }
        }catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    /*public static void prepareNSSCertStore(DockerTlsServerInstance tlsServerInstance) {
        if (!isPk12utilCommandAvailable()) {
            throw new RuntimeException("Missing libnss3-tools! Please install it before continuing.");
        }

        //TODO This is not really nice
        try {
            boolean x = new File(Paths.get("X509-Testsuite/resources/nssdb_tmp").toAbsolutePath().toString()).mkdir();
            Runtime.getRuntime().exec(new String[] {"certutil", "-N", "-d", "sql:./X509-Testsuite/resources/nssdb_tmp/"});
            ProcessBuilder builder =
                    new ProcessBuilder(
                            "openssl",
                            "pkcs12",
                            "-export",
                            "-inkey",
                            "X509-Testsuite/resources/static-root/private-key.pem",
                            "-in",
                            "X509-Testsuite/resources/static-root/root-cert.pem",
                            "-out",
                            "X509-Testsuite/resources/static-root/x509_anvil_nss_server.p12",
                            "-name",
                            "nss-server-cert",
                            "-passout",
                            "pass:password");

            builder.redirectErrorStream(true);
            Process process = builder.start();
            process.waitFor();

            Runtime.getRuntime().exec(new String[] {"pk12util", "-i", "X509-Testsuite/resources/static-root/x509_anvil_nss_server.p12", "-d", "sql:./X509-Testsuite/resources/nssdb_tmp/", "-W", "password"});
            Runtime.getRuntime().exec(new String[] {"certutil", "-A", "-n", "X509-Anvil-CA", "-t", "CT,,", "-i", "X509-Testsuite/resources/out/root_cert.pem", "-d", "sql:./X509-Testsuite/resources/nssdb_tmp/"});
        } catch (InterruptedException | IOException e) {
            LOGGER.error("Failed to create nss certificate container.");
            LOGGER.error(e);
            System.exit(0);
        }
    }*/

    private static boolean isPk12utilCommandAvailable() {
        try {
            Process process = new ProcessBuilder("which", "pk12util").start();
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
