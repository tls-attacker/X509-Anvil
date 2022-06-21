package de.rub.nds.x509anvil.framework.model;

import de.rub.nds.x509anvil.framework.TestContext;
import de.rub.nds.x509anvil.framework.model.parameter.DerivationParameter;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rwth.swc.coffee4j.model.Combination;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

public class ParameterCombination {
    private static final Logger LOGGER = LogManager.getLogger();

    private final List<DerivationParameter> parameters;
    private DerivationScope derivationScope;

    public ParameterCombination(List<DerivationParameter> parameters) {
        this.parameters = parameters;
    }

    public ParameterCombination(List<DerivationParameter> parameters, DerivationScope derivationScope) {
        this.parameters = parameters;
        this.derivationScope = derivationScope;
        // TODO static parameters
    }

    public static ParameterCombination fromCombination(Combination combination) {
        List<DerivationParameter> parameters = new ArrayList<>();
        combination.getParameterValueMap().keySet().forEach(key -> {
            Object obj = combination.getParameterValueMap().get(key).get();
            if (obj instanceof DerivationParameter) {
                parameters.add((DerivationParameter) obj);
            } else {
                LOGGER.warn("Unsupported parameter type ignored");
            }
        });
        return new ParameterCombination(parameters);
    }

    public static ParameterCombination fromArgumentsAccessor(ArgumentsAccessor argumentsAccessor, DerivationScope derivationScope) {
        List<DerivationParameter> parameters = new ArrayList<>();
        for (Object obj : argumentsAccessor.toList()) {
            if (obj instanceof DerivationParameter) {
                parameters.add((DerivationParameter) obj);
            } else {
                LOGGER.warn("Unsupported parameter type ignored");
            }
        }
        return new ParameterCombination(parameters, derivationScope);
    }


    public DerivationParameter getParameter(ParameterIdentifier parameterIdentifier) {
        for (DerivationParameter param : parameters) {
            if (param.getParameterIdentifier().equals(parameterIdentifier)) {
                return param;
            }
        }
        return null;
    }

    public void applyToConfig(X509CertificateChainConfig config, TestContext context) {
        for (DerivationParameter param : parameters) {
            // TODO: isAutoApplyToConfig check
            param.applyToConfig(config, context);
        }
        // TODO: Config post processing
    }

    @Override
    public String toString() {
        StringJoiner joiner = new StringJoiner(", ");
        for (DerivationParameter parameter : parameters) {
            joiner.add(parameter.toString());
        }
        return joiner.toString();
    }
}
