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
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.x509.X509CertificateUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainConfig implements AnvilConfig {
    private static final Logger LOGGER = LogManager.getLogger();

    private int chainLength;
    private int intermediateCertsModeled;
    private boolean staticRoot;

    private X509CertificateConfig rootCertificateConfig = null;
    private final List<X509CertificateConfig> intermediateCertificateConfigs = new ArrayList<>();
    private X509CertificateConfig entityCertificateConfig = null;

    private boolean initialized = false;


    public void initializeChain(int chainLength, int intermediateCertsModeled) {
        if (initialized) {
            throw new IllegalStateException("Config is already initialized");
        }

        this.chainLength = chainLength;
        this.intermediateCertsModeled = intermediateCertsModeled;

        TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
        this.staticRoot = testConfig.getUseStaticRootCertificate();


        if (staticRoot) {
            try {
                rootCertificateConfig = X509CertificateUtil.loadStaticCertificateConfig(testConfig.getStaticRootCertificateFile(), testConfig.getStaticRootPrivateKeyFile());
            }
            catch (IOException | InvalidKeySpecException e) {
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
                X509CertificateConfig config = X509CertificateUtil.getDefaultCertificateConfig(false, "cert_inter_" + i);
                if (i == intermediateCertsModeled - 1 && intermediateCertsModeled < chainLength - 2) {
                    config.setSharedConfig(true);
                }
                intermediateCertificateConfigs.add(config);
            }
        }

        // Generate entity config
        if (chainLength == 1) {
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

    public X509CertificateConfig getConfigByChainPosition(int chainPosition) {
        int entityPosition = Integer.min(chainLength, intermediateCertsModeled + 2) - 1;
        if (chainPosition == 0) {
            if (rootCertificateConfig == null) {
                throw new IllegalArgumentException("Config for root certificate does not exist");
            }
            return rootCertificateConfig;
        }
        else if (chainPosition > 0 && chainPosition < entityPosition) {
            if (chainPosition - 1 >= intermediateCertificateConfigs.size()) {
                throw new IllegalArgumentException("Config for intermediate certificate at position " + chainPosition + " does not exist");
            }
            return intermediateCertificateConfigs.get(chainPosition - 1);
        }
        else if (chainPosition == entityPosition) {
            if (entityCertificateConfig == null) {
                throw new IllegalArgumentException("Config for entity certificate does not exist");
            }
            return entityCertificateConfig;
        }
        else {
            throw new IllegalArgumentException("Invalid chain position");
        }
    }

    public int getIntermediateCertsModeled() {
        return intermediateCertsModeled;
    }

    public boolean isStaticRoot() {
        return staticRoot;
    }

    public boolean isInitialized() {
        return initialized;
    }
}
