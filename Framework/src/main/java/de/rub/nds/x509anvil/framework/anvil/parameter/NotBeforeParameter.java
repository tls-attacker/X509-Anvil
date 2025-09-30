/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import java.util.ArrayList;
import java.util.List;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class NotBeforeParameter extends CertificateSpecificParameter<NotBeforeValue> {

    public NotBeforeParameter(ParameterScope parameterScope) {
        super(
                new ParameterIdentifier(X509AnvilParameterType.NOT_BEFORE, parameterScope),
                NotBeforeValue.class);
    }

    public NotBeforeParameter(NotBeforeValue selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, NotBeforeValue> generateValue(
            NotBeforeValue selectedValue) {
        return new NotBeforeParameter(
                selectedValue, this.getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, NotBeforeValue>>
            getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, NotBeforeValue>> parameterValues =
                new ArrayList<>();
        for (NotBeforeValue value : NotBeforeValue.values()) {
            parameterValues.add(generateValue(value));
        }
        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        switch (getSelectedValue()) {
            case UTC_TIME:
                certificateConfig.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                certificateConfig.setNotBefore(
                        new DateTime(2022, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
            case UTC_TIME_EARLIEST:
                certificateConfig.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                certificateConfig.setNotBefore(
                        new DateTime(1950, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
            /*case GENERALIZED_TIME:
                certificateConfig.setDefaultNotBeforeEncoding(
                        ValidityEncoding.GENERALIZED_TIME_UTC);
                certificateConfig.setNotBefore(
                        new DateTime(2022, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
            case GENERALIZED_TIME_BEFORE_1950:
                certificateConfig.setDefaultNotBeforeEncoding(
                        ValidityEncoding.GENERALIZED_TIME_UTC);
                certificateConfig.setNotBefore(
                        new DateTime(1950, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;*/
        }
    }
}
