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
import de.rub.nds.x509anvil.framework.constants.CertificateChainPosType;
import de.rub.nds.x509anvil.framework.x509.X509CertificateConfigUtil;
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


    public void initializeChain(int chainLength, int intermediateCertsModeled, boolean staticRoot) {
        if (initialized) {
            throw new IllegalStateException("Config is already initialized");
        }

        this.chainLength = chainLength;
        this.intermediateCertsModeled = intermediateCertsModeled;

        TestConfig testConfig = ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate()).getTestConfig();
        this.staticRoot = staticRoot;


        if (staticRoot) {
            try {
                rootCertificateConfig = X509CertificateConfigUtil.loadStaticCertificateConfig(testConfig.getStaticRootCertificateFile(), testConfig.getStaticRootPrivateKeyFile());
            }
            catch (IOException | InvalidKeySpecException e) {
                LOGGER.error("Unable to load static root certificate and its private key", e);
                throw new IllegalArgumentException("Unable to load static root certificate and its private key", e);
            }
        }
        else {
            // We need to generate our own root
            rootCertificateConfig = X509CertificateConfigUtil.getDefaultCaCertificateConfig("cert_root", true, CertificateChainPosType.ROOT);
        }

        // Generate configs for intermediate certificates
        for (int i = 0; i < chainLength - 2; i++) {
            if (i < intermediateCertsModeled) {
                X509CertificateConfig config = X509CertificateConfigUtil
                        .getDefaultCaCertificateConfig("cert_intermediate_" + i,false, CertificateChainPosType.INTERMEDIATE);
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
            entityCertificateConfig = X509CertificateConfigUtil.getDefaultCertificateConfig("cert_entity", false, CertificateChainPosType.ENTITY);
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

    public X509CertificateConfig getIntermediateConfig(int index) {
        return intermediateCertificateConfigs.get(index);
    }

    public X509CertificateConfig getIssuerConfigOf(X509CertificateConfig subject) {
        List<X509CertificateConfig> certificateConfigList = getCertificateConfigList();
        if (!certificateConfigList.contains(subject)) {
            throw new IllegalArgumentException("Subject config is not part of the chain");
        }
        if (certificateConfigList.indexOf(subject) == 0) {
            if (subject.isSelfSigned()) {
                return subject;
            }
            throw new IllegalArgumentException("Subject config is root config and not self-signed");
        }

        return certificateConfigList.get(certificateConfigList.indexOf(subject) - 1);
    }

    public List<X509CertificateConfig> getCertificateConfigList() {
        List<X509CertificateConfig> certificateConfigList = new ArrayList<>();

        if (chainLength == 0) {
            return certificateConfigList;
        }
        else if (chainLength == 1) {
            certificateConfigList.add(rootCertificateConfig);
            return certificateConfigList;
        }
        else {
            certificateConfigList.add(rootCertificateConfig);
            certificateConfigList.addAll(intermediateCertificateConfigs);
            certificateConfigList.add(entityCertificateConfig);
            return certificateConfigList;
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
