/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.model.config.AnvilConfig;
import de.rub.nds.asn1.parser.X509Parser;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509attacker.x509.X509Certificate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainConfig2 implements AnvilConfig {
    private static final Logger LOGGER = LogManager.getLogger();

    private int chainLength;
    private int intermediateCertsModeled;

    private boolean staticRoot;
    private X509Certificate staticRootCertificate;

    private X509CertificateConfig rootCertificateConfig = null;
    private final List<X509CertificateConfig> intermediateCertificateConfigs = new ArrayList<>();
    private X509CertificateConfig entityCertificateConfig = null;

    private boolean initialized = false;


    public void initializeChain(int chainLength, int intermediateCertsModeled, boolean staticRoot) {
        if (initialized) {
            throw new IllegalStateException("Config is already initialized");
        }

        this.chainLength = chainLength;
        this.intermediateCertsModeled = intermediateCertsModeled;

        TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
        this.staticRoot = testConfig.getUseStaticRootCertificate();


        if (staticRoot) {
            try {
                X509Parser x509Parser = new X509Parser(new File(testConfig.getStaticRootCertificateFile()));
                staticRootCertificate = x509Parser.parse();
                staticRootCertificate.setKeyFile(new File(testConfig.getStaticRootPrivateKeyFile()));
            }
            catch (IOException e) {
                LOGGER.error("Unable to load static root certificate and its private key", e);
                throw new IllegalArgumentException("Unable to load static root certificate and its private key", e);
            }
        }
        else {
            // We need to generate our own root
            rootCertificateConfig = X509CertificateUtil.getDefaultCertificateConfig(true, "cert_root");
        }

        // Generate configs for intermediate certificates
        for (int i = 0; i < chainLength - 2; i++) {
            if (i < intermediateCertsModeled) {
                intermediateCertificateConfigs.add(X509CertificateUtil.getDefaultCertificateConfig(false, "cert_inter_" + i));
            }
        }

        // Generate entity config
        if (!staticRoot && chainLength == 1) {
            entityCertificateConfig = rootCertificateConfig;
        }
        else {
            entityCertificateConfig = X509CertificateUtil.getDefaultCertificateConfig(false, "cert_entity");
        }

        initialized = true;
    }

    public int getChainLength() {
        return chainLength;
    }

    public X509CertificateConfig getEntityCertificateConfig() {
        return entityCertificateConfig;
    }

    public X509CertificateConfig getRootCertificateConfig() {
        return rootCertificateConfig;
    }

    public List<X509CertificateConfig> getIntermediateCertificateConfigs() {
        return intermediateCertificateConfigs;
    }

    public int getIntermediateCertsModeled() {
        return intermediateCertsModeled;
    }

    public boolean isStaticRoot() {
        return staticRoot;
    }

    public X509Certificate getStaticRootCertificate() {
        return staticRootCertificate;
    }

    public boolean isInitialized() {
        return initialized;
    }
}
