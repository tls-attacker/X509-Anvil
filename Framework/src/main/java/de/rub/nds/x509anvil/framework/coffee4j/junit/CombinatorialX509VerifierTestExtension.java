/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.coffee4j.junit;

import de.rub.nds.x509anvil.framework.annotations.TestChooser;
import de.rwth.swc.coffee4j.junit.CombinatorialTestExecutionCallback;
import de.rwth.swc.coffee4j.junit.CombinatorialTestExtension;
import de.rwth.swc.coffee4j.junit.CombinatorialTestInvocationContext;
import de.rwth.swc.coffee4j.junit.CombinatorialTestMethodContext;
import de.rwth.swc.coffee4j.junit.provider.configuration.ConfigurationLoader;
import de.rwth.swc.coffee4j.junit.provider.model.ModelLoader;
import de.rwth.swc.coffee4j.model.InputParameterModel;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManager;
import de.rwth.swc.coffee4j.model.manager.CombinatorialTestConsumerManagerConfiguration;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.platform.commons.util.AnnotationUtils;
import org.junit.platform.commons.util.Preconditions;

import java.lang.reflect.Method;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class CombinatorialX509VerifierTestExtension extends CombinatorialTestExtension {

    @Override
    public boolean supportsTestTemplate(ExtensionContext extensionContext) {
        if (!extensionContext.getTestMethod().isPresent()) {
            return false;
        }

        Method testMethod = extensionContext.getRequiredTestMethod();
        if (!AnnotationUtils.isAnnotated(testMethod, TestChooser.class)) {
            return false;
        }

        return CombinatorialTestMethodContext.checkAggregatorOrder(testMethod);
    }

    @Override
    public Stream<TestTemplateInvocationContext>
        provideTestTemplateInvocationContexts(ExtensionContext extensionContext) {
        Method testMethod = extensionContext.getRequiredTestMethod();
        CombinatorialTestConsumerManagerConfiguration consumerManagerConfiguration =
            new ConfigurationLoader().load(extensionContext);
        TestInputIterator testInputIterator = new TestInputIterator(extensionContext);
        InputParameterModel ipm = new ModelLoader().load(extensionContext);
        CombinatorialTestConsumerManager testConsumerManager =
            new CombinatorialTestConsumerManager(consumerManagerConfiguration, testInputIterator::add, ipm);

        // TODO diagnose constraints

        testConsumerManager.generateInitialTests();

        CombinatorialTestExtension.getStore(extensionContext).put(CombinatorialTestExecutionCallback.REPORTERS_KEY,
            consumerManagerConfiguration.getExecutionReporters());
        CombinatorialTestExtension.getStore(extensionContext).put(CombinatorialTestExecutionCallback.MANAGER_KEY,
            testConsumerManager);

        CombinatorialTestMethodContext methodContext = new CombinatorialTestMethodContext(testMethod, ipm);
        X509CombinatorialTestNameFormatter testNameFormatter = new X509CombinatorialTestNameFormatter("TODO"); // TODO

        // TODO test name formatting

        Preconditions.condition(testInputIterator.hasNext(), "No test inputs were generated!");
        return StreamSupport.stream(Spliterators.spliteratorUnknownSize(testInputIterator, Spliterator.ORDERED), false)
            .map(testInput -> new CombinatorialTestInvocationContext(testNameFormatter, methodContext, testInput));
    }
}
