package de.rub.nds.x509anvil.framework.verifier.adapter.util;

import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class NSSPkcs12Util {

    protected static final Logger LOGGER = LogManager.getLogger();

    public static void execSetup() {
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

    private static boolean isPk12utilCommandAvailable() {
        try {
            Process process = new ProcessBuilder("which", "pk12util").start();
            return process.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
