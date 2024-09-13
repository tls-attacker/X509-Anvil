/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.anvil.TestConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.CertificateChainPositionType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainConfig {
    private static final Logger LOGGER = LogManager.getLogger();

    private int chainLength;
    private int intermediateCertsModeled;

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

        rootCertificateConfig =
            X509CertificateConfigUtil.getDefaultCaCertificateConfig(true, CertificateChainPositionType.ROOT);

        // Generate configs for intermediate certificates
        for (int i = 0; i < chainLength - 2; i++) {
            if (i < intermediateCertsModeled) {
                X509CertificateConfig config = X509CertificateConfigUtil.getDefaultCaCertificateConfig(false,
                    CertificateChainPositionType.INTERMEDIATE);
                intermediateCertificateConfigs.add(config);
            }
        }

        // Generate entity config
        if (chainLength == 1) {
            entityCertificateConfig = rootCertificateConfig;
        } else {
            entityCertificateConfig =
                X509CertificateConfigUtil.getDefaultCertificateConfig(false, CertificateChainPositionType.ENTITY);
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
        } else if (chainLength == 1) {
            certificateConfigList.add(rootCertificateConfig);
            return certificateConfigList;
        } else {
            certificateConfigList.add(rootCertificateConfig);
            certificateConfigList.addAll(intermediateCertificateConfigs);
            certificateConfigList.add(entityCertificateConfig);
            return certificateConfigList;
        }

    }

    public int getIntermediateCertsModeled() {
        return intermediateCertsModeled;
    }

    public boolean isInitialized() {
        return initialized;
    }
}
