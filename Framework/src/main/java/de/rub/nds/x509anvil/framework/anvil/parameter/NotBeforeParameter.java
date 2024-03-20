/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.value.NotBeforeValue;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;

import java.util.ArrayList;
import java.util.List;

public class NotBeforeParameter extends CertificateSpecificParameter<NotBeforeValue> {

    public NotBeforeParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.NOT_BEFORE, parameterScope), NotBeforeValue.class);
    }

    public NotBeforeParameter(NotBeforeValue selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, NotBeforeValue>
        generateValue(NotBeforeValue selectedValue) {
        return new NotBeforeParameter(selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, NotBeforeValue>> getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, NotBeforeValue>> parameterValues = new ArrayList<>();
        for (NotBeforeValue value : NotBeforeValue.values()) {
            parameterValues.add(generateValue(value));
        }
        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        switch (getSelectedValue()) {
            case UTC_TIME:
                certificateConfig.setNotBeforeTimeType(TimeType.UTC_TIME);
                certificateConfig.setNotBeforeValue("220101000000Z");
                break;
            case UTC_TIME_EARLIEST:
                certificateConfig.setNotBeforeTimeType(TimeType.UTC_TIME);
                certificateConfig.setNotBeforeValue("500101000000Z");
                break;
            case GENERALIZED_TIME:
                certificateConfig.setNotBeforeTimeType(TimeType.GENERALIZED_TIME);
                certificateConfig.setNotBeforeValue("20220101000000Z");
                break;
            case GENERALIZED_TIME_BEFORE_1950:
                certificateConfig.setNotBeforeTimeType(TimeType.GENERALIZED_TIME);
                certificateConfig.setNotBeforeValue("19400101000000Z");
                break;
        }
    }
}
