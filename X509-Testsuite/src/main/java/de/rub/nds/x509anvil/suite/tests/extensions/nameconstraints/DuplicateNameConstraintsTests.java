package de.rub.nds.x509anvil.suite.tests.extensions.nameconstraints;

import de.rub.nds.anvilcore.annotation.AnvilTest;
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

public class DuplicateNameConstraintsTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-c1a6acb0d3")
    public void duplicateIdenticalNameConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
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
            config.addExtensions(nameConstraintsConfig);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-c1a6acb1d3")
    public void duplicateDifferentNameConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
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

            NameConstraintsConfig nameConstraintsConfigDifferent = new NameConstraintsConfig();
            nameConstraintsConfigDifferent.setPresent(true);
            nameConstraintsConfigDifferent.setCritical(true);
            GeneralSubtrees permittedTreesDifferent = new GeneralSubtrees("permittedSubtreesDiff");
            GeneralSubtree permittedTreeDifferent = new GeneralSubtree("permittedSubtreeDiff", 0, 4);
            GeneralName permittedNameDifferent = new GeneralName("permittedNameDiff");
            permittedNameDifferent.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.DNS_NAME);
            permittedNameDifferent.setGeneralNameConfigValue("www.tls-attacker.com");
            permittedTreeDifferent.setBase(permittedNameDifferent);
            permittedTreesDifferent.setGeneralSubtrees(List.of(permittedTreeDifferent));
            nameConstraintsConfigDifferent.setPermittedSubtrees(permittedTreesDifferent);
            config.addExtensions(nameConstraintsConfigDifferent);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-c1a6acb1d4")
    public void duplicateDifferentOrderNameConstraintsIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
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

            NameConstraintsConfig nameConstraintsConfigDifferent = new NameConstraintsConfig();
            nameConstraintsConfigDifferent.setPresent(true);
            nameConstraintsConfigDifferent.setCritical(true);
            GeneralSubtrees permittedTreesDifferent = new GeneralSubtrees("permittedSubtreesDiff");
            GeneralSubtree permittedTreeDifferent = new GeneralSubtree("permittedSubtreeDiff", 0, 4);
            GeneralName permittedNameDifferent = new GeneralName("permittedNameDiff");
            permittedNameDifferent.setGeneralNameChoiceTypeConfig(GeneralNameChoiceType.DNS_NAME);
            permittedNameDifferent.setGeneralNameConfigValue("www.tls-attacker.com");
            permittedTreeDifferent.setBase(permittedNameDifferent);
            permittedTreesDifferent.setGeneralSubtrees(List.of(permittedTreeDifferent));
            nameConstraintsConfigDifferent.setPermittedSubtrees(permittedTreesDifferent);

            config.addExtensions(nameConstraintsConfigDifferent);
            config.addExtensions(nameConstraintsConfig);
        });
    }
}
