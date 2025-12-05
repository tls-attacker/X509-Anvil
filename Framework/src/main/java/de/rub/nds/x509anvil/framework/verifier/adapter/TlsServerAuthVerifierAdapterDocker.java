/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.verifier.adapter;

import com.github.dockerjava.api.model.AccessMode;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Volume;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.docker.DockerTlsClientInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.exceptions.TlsVersionNotFoundException;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfigDocker;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import de.rub.nds.x509anvil.framework.verifier.adapter.util.NSSPkcs12Util;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TlsServerAuthVerifierAdapterDocker extends TlsServerAuthVerifierAdapter {
    protected static final Logger LOGGER = LogManager.getLogger();

    private static final Map<String, DockerTlsClientInstance> tlsClientInstances = new HashMap<>();

    private final DockerTlsClientInstance currentClientInstance;
    protected int realPort;

    private TlsServerAuthVerifierAdapterDocker(DockerTlsClientInstance instance, String type) {
        super("localhost", 0);
        this.currentClientInstance = instance;

        if(TlsImplementationType.fromString(type) == TlsImplementationType.OPENSSL) {
            config.setAddRenegotiationInfoExtension(true);
        }
        if(TlsImplementationType.fromString(type) == TlsImplementationType.WOLFSSL) {
            config.setAddRenegotiationInfoExtension(false);
            config.getDefaultServerSupportedSignatureAndHashAlgorithms()
                    .removeAll(Arrays.asList(
                            SignatureAndHashAlgorithm.DSA_SHA224,
                            SignatureAndHashAlgorithm.ECDSA_SHA224,
                            SignatureAndHashAlgorithm.RSA_SHA224
                    ));
        }
    }

    public static TlsServerAuthVerifierAdapterDocker fromConfig(
            TlsAuthVerifierAdapterConfigDocker config) {
        DockerTlsClientInstance instance = spinUpServer(config);
        return new TlsServerAuthVerifierAdapterDocker(instance, config.getImage());
    }

    private static DockerTlsClientInstance spinUpServer(TlsAuthVerifierAdapterConfigDocker config) {
        String key = config.getImage() + ":" + config.getVersion();
        if (tlsClientInstances.containsKey(key)) {
            return tlsClientInstances.get(key);
        }

        DockerTlsClientInstance tlsClientInstance = null;
        LOGGER.info("Attempting to start TLS Server Docker image...");
        try {
            de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsClientInstanceBuilder builder =
                    DockerTlsManagerFactory.getTlsClientBuilder(
                                    TlsImplementationType.fromString(config.getImage()),
                                    config.getVersion())
                            .hostConfigHook(TlsServerAuthVerifierAdapterDocker::applyConfig)
                            .certificatePath("/x509-anv-resources/out/root_cert.pem")
                            .additionalParameters(supplementStartCommand(TlsImplementationType.fromString(config.getImage())));;
            if(TlsImplementationType.fromString(config.getImage()) == TlsImplementationType.NSS) {
                //NSSPkcs12Util.execSetup();
                builder.certificatePath("sql:/x509-anv-resources/nss_db/").additionalParameters("-R X509-Anvil-CA -Q");
            }

            tlsClientInstance = builder.build();
        } catch (TlsVersionNotFoundException e) {
            LOGGER.error("Unknown Version {} of {}", config.getVersion(), config.getImage());
            System.exit(-1);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        tlsClientInstance.start();
        tlsClientInstances.put(key, tlsClientInstance);
        return tlsClientInstance;
    }

    private static String supplementStartCommand(TlsImplementationType tlsImplementationType) {
        return (switch (tlsImplementationType) {
            case OPENSSL, LIBRESSL ->
                    "-verify 5 -verify_return_error";
            case BOTAN -> "--skip-hostname-check";
            default -> "";
        });
    }

    private static HostConfig applyConfig(HostConfig config) {
        String hostPath = X509Util.RESOURCES_PATH.getAbsolutePath();
        config.withBinds(new Bind(hostPath, new Volume("/x509-anv-resources/"), AccessMode.ro));
        config.withExtraHosts("tls-attacker.com:host-gateway");
        config.withAutoRemove(true);
        return config;
    }

    @Override
    public void runCommandInBackground() {
        try {
            Thread.sleep(20);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        currentClientInstance.connect("tls-attacker.com", realPort);
    }

    public static void stopContainers() {
        for (DockerTlsClientInstance instance : tlsClientInstances.values()) {
            try {
                instance.kill();
            } catch (Exception e) {
                // Container is already dead, so it's alright :-)
            }
        }
    }
}
