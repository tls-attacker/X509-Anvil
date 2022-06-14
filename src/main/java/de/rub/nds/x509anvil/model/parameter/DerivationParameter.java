package de.rub.nds.x509anvil.model.parameter;

import de.rub.nds.x509anvil.TestContext;
import de.rub.nds.x509anvil.model.DerivationScope;
import de.rub.nds.x509anvil.model.ParameterIdentifier;
import de.rub.nds.x509anvil.model.ParameterScope;
import de.rub.nds.x509anvil.model.ParameterType;
import de.rub.nds.x509anvil.model.constraint.ValueConstraint;
import de.rub.nds.x509anvil.x509.config.X509CertificateChainConfig;
import de.rwth.swc.coffee4j.model.Parameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public abstract class DerivationParameter<T> {
    private static final Logger LOGGER = LogManager.getLogger();

    private T selectedValue;
    private final Class<T> valueClass;
    private final ParameterIdentifier parameterIdentifier;

    public DerivationParameter(ParameterType parameterType, ParameterScope parameterScope, Class<T> valueClass) {
        this.parameterIdentifier = new ParameterIdentifier(parameterScope, parameterType);
        this.valueClass = valueClass;
    }

    public abstract DerivationParameter<T> generateValue(T selectedValue);

    public abstract List<DerivationParameter<T>> getParameterValues(TestContext testContext, DerivationScope derivationScope);

    public List<DerivationParameter<T>> getConstrainedParameterValues(TestContext testContext, DerivationScope derivationScope) {
        List<DerivationParameter<T>> constrainedParameterValues = new ArrayList<>();
        if (derivationScope.hasExplicitValues(parameterIdentifier)) {
            return getExplicitValues(derivationScope);
        }
        else {
            constrainedParameterValues = getParameterValues(testContext, derivationScope).stream().filter(value ->
                    valueApplicableUnderAllConstraints(derivationScope.getValueConstraints(), value.getSelectedValue())
            ).collect(Collectors.toList());
        }
        return constrainedParameterValues;
    }

    public List<DerivationParameter<T>> getExplicitValues(DerivationScope derivationScope) {
        // TODO
        return Collections.emptyList();
    }

    public abstract void applyToConfig(X509CertificateChainConfig config, TestContext testContext);

    public void postProcessConfig(X509CertificateChainConfig config, TestContext testContext) {}

    public Parameter.Builder getParameterBuilder(TestContext testContext, DerivationScope derivationScope) {
        List<DerivationParameter<T>> constrainedParameterValues = getConstrainedParameterValues(testContext, derivationScope);
        return Parameter.parameter(parameterIdentifier.toString()).value(constrainedParameterValues.toArray());
    }


    public T getSelectedValue() {
        return selectedValue;
    }

    public void setSelectedValue(T selectedValue) {
        this.selectedValue = selectedValue;
    }

    public Class<T> getValueClass() {
        return valueClass;
    }

    public ParameterIdentifier getParameterIdentifier() {
        return parameterIdentifier;
    }


    private boolean valueApplicableUnderAllConstraints(List<ValueConstraint> valueConstraints, T value) {
        for (ValueConstraint constraint : valueConstraints) {
            if (constraint.getAffectedParameter().equals(parameterIdentifier)) {
                if (!valueApplicableUnderConstraint(constraint, value)) {
                    return false;
                }
            }
        }
        return true;
    }

    private boolean valueApplicableUnderConstraint(ValueConstraint constraint, T value) {
        // TODO
        return true;
    }
}
