/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.context.AnvilContext;
import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilContextDelegate;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.constants.KeyTypeLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.security.KeyPair;
import java.util.List;
import java.util.stream.Collectors;

public class KeyTypeParameter extends CertificateSpecificParameter<KeyTypeLengthPair> {

    public KeyTypeParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.KEY_TYPE, parameterScope), KeyTypeLengthPair.class);
    }

    public KeyTypeParameter(ParameterScope parameterScope, KeyTypeLengthPair value) {
        this(parameterScope);
        setSelectedValue(value);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, KeyTypeLengthPair>
        generateValue(KeyTypeLengthPair selectedValue) {
        return new KeyTypeParameter(getParameterIdentifier().getParameterScope(), selectedValue);
    }

    @Override
    protected List<DerivationParameter> getNonNullParameterValues(DerivationScope derivationScope) {
        FeatureReport featureReport =
            ((X509AnvilContextDelegate) AnvilContext.getInstance().getApplicationSpecificContextDelegate())
                .getFeatureReport();
        List<KeyTypeLengthPair> supportedKeyLength;
        if (getParameterScope().isEntity()) {
            supportedKeyLength = featureReport.getSupportedEntityKeyLengths();
        } else {
            supportedKeyLength = featureReport.getSupportedKeyLengths();
        }
        return supportedKeyLength.stream().map(this::generateValue).collect(Collectors.toList());
    }

    @Override
    protected void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setKeyType(getSelectedValue().getKeyType());
        certificateConfig.setKeyLength(getSelectedValue().getKeyLength());
        KeyPair keyPair = X509CertificateConfigUtil.generateKeyPair(getSelectedValue().getKeyType(),
            certificateConfig.getCertificateName(), getSelectedValue().getKeyLength());
        certificateConfig.setKeyPair(keyPair);
    }
}
