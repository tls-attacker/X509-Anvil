/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.anvil.parameter.value.NotAfterValue;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;

import java.util.ArrayList;
import java.util.List;

public class NotAfterParameter extends CertificateSpecificParameter<NotAfterValue> {

    public NotAfterParameter(ParameterScope parameterScope) {
        super(new ParameterIdentifier(X509AnvilParameterType.NOT_AFTER, parameterScope), NotAfterValue.class);
    }

    public NotAfterParameter(NotAfterValue selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, NotAfterValue>
        generateValue(NotAfterValue selectedValue) {
        return new NotAfterParameter(selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, NotAfterValue>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, NotAfterValue>> parameterValues = new ArrayList<>();
        for (NotAfterValue value : NotAfterValue.values()) {
            parameterValues.add(generateValue(value));
        }
        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        switch (getSelectedValue()) {
            case UTC_TIME:
                certificateConfig.setNotAfterTimeType(TimeType.UTC_TIME);
                certificateConfig.setNotAfterValue("250101000000Z");
                break;
            case UTC_TIME_LATEST:
                certificateConfig.setNotAfterTimeType(TimeType.UTC_TIME);
                certificateConfig.setNotAfterValue("491231235959Z");
                break;
            case GENERALIZED_TIME:
                certificateConfig.setNotAfterTimeType(TimeType.GENERALIZED_TIME);
                certificateConfig.setNotAfterValue("20500101000000Z");
                break;
            case GENERALIZED_TIME_BEFORE_2050:
                certificateConfig.setNotAfterTimeType(TimeType.GENERALIZED_TIME);
                certificateConfig.setNotAfterValue("20250101000000Z");
                break;
            case NO_WELL_DEFINED_EXPIRATION:
                certificateConfig.setNotAfterTimeType(TimeType.GENERALIZED_TIME);
                certificateConfig.setNotAfterValue("99991231235959Z");
                break;
        }
    }
}
