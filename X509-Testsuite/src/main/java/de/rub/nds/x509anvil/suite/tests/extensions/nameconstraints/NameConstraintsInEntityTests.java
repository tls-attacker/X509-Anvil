package de.rub.nds.x509anvil.suite.tests.extensions.nameconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.NameConstraintsConfig;
import de.rub.nds.x509attacker.constants.GeneralNameChoiceType;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralSubtree;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralSubtrees;

import java.util.List;

public class NameConstraintsInEntityTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-c1a6aca5d3")
    public void nameConstraintsInEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            NameConstraintsConfig nameConstraintsConfig = new NameConstraintsConfig();
            nameConstraintsConfig.setPresent(true);
            nameConstraintsConfig.setCritical(true);
            GeneralSubtrees permittedTrees = new GeneralSubtrees("permittedSubtrees");
            GeneralSubtree permittedTree = new GeneralSubtree("permittedSubtree", 0, 5);
            GeneralName permittedName = new GeneralName("permittedName");
            permittedName.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.DNS_NAME);
            permittedName.setGeneralNameConfigValue("tls-attacker.com");
            permittedTree.setBase(permittedName);
            permittedTrees.setGeneralSubtrees(List.of(permittedTree));
            nameConstraintsConfig.setPermittedSubtrees(permittedTrees);
            config.addExtensions(nameConstraintsConfig);
            config.setIncludeExtensions(true);
        });
    }
}
