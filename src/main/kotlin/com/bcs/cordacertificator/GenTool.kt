package com.bcs.cordacertificator

import net.corda.nodeapi.internal.crypto.X509KeyStore
import net.corda.nodeapi.internal.crypto.X509Utilities
import java.nio.file.Path
import net.corda.core.identity.CordaX500Name
import org.apache.commons.cli.*
import java.nio.file.Paths


fun main(args: Array<String>) {
    val options = Options()

    val rootName = Option("rn", "root-names", true, "Sets the name for the root zone.")
    rootName.isRequired = true

    val rootGroup = OptionGroup()

    val rootGen = Option("rg", "root-gen", true, "Generate root zone certificates and store them in this directory.")
    rootGen.isRequired = false
    rootGroup.addOption(rootGen)

    val rootRead = Option("rr", "root-read", true, "Use root zone certs in this directory.")
    rootRead.isRequired = false
    rootGroup.addOption(rootRead)

    rootGroup.isRequired = true

    val nodeNames = Option("nn", "node-names", true, "Generate the following nodes")
    nodeNames.isRequired = false
    nodeNames.args = Option.UNLIMITED_VALUES

    val nodeDir = Option("nd", "node-dir", true, "Put the nodes' certificates under this directory")
    nodeDir.isRequired = false

    options.addOption(rootName)
    options.addOptionGroup(rootGroup)
    options.addOption(nodeNames)
    options.addOption(nodeDir)

    val parser = DefaultParser()
    val formatter = HelpFormatter()
    val cmd: CommandLine

    try {
        cmd = parser.parse(options, args)
    } catch (e: ParseException) {
        System.out.println(e.message)
        formatter.printHelp("gentool", options)
        return System.exit(1) // Return to help IntelliJ/Kotlin figure out unreachables.
    }

    System.console().printf("Please input the root keystores' password: ")
    val rootPass = String(System.console().readPassword())
    System.console().printf("Please input the node keystores' password: ")
    val nodePass = String(System.console().readPassword())

    val parsedRootName = CordaX500Name.parse(cmd.getOptionValue("rn"))

    val zoneCerts: ZoneCerts
    if (cmd.hasOption("rg")) {
        val rootPath = Paths.get(cmd.getOptionValue("rg"))
        val doormanName = parsedRootName.copy(organisation = parsedRootName.organisation + " Doorman")
        val netmapName = parsedRootName.copy(organisation = parsedRootName.organisation + " Network Map")
        zoneCerts = generateRootZone(parsedRootName, doormanName, netmapName)
        saveRootCerts(zoneCerts, rootPath, rootPass)
    } else {
        val rootPath = Paths.get(cmd.getOptionValue("rr"))
        val rootStore = X509KeyStore.fromFile(rootPath.resolve("rootstore.jks"), rootPass, createNew = false)
        val doormanStore = X509KeyStore.fromFile(rootPath.resolve("doormanstore.jks"), rootPass, createNew = false)
        val netmapStore = X509KeyStore.fromFile(rootPath.resolve("networkmapstore.jks"), rootPass, createNew = false)
        val rootCKP = rootStore.getCertificateAndKeyPair(X509Utilities.CORDA_ROOT_CA)
        val doormanCKP = doormanStore.getCertificateAndKeyPair(X509Utilities.CORDA_INTERMEDIATE_CA)
        val netmapCKP = netmapStore.getCertificateAndKeyPair("cordanetworkmapca")
        zoneCerts = ZoneCerts(rootCKP, doormanCKP, netmapCKP)
    }

    if (cmd.hasOption("nn")) {
        val nodePath = Paths.get(cmd.getOptionValue("nd"))
        cmd.getOptionValues("nn").map {
            val name = CordaX500Name.parse(it)
            val nodeCerts = generateNodeCerts(name, zoneCerts)
            saveNodeCerts(nodeCerts, zoneCerts, nodePath, nodePass)
        }
    }
}

/**
 * Helper function to save the zone certs into keystores under a given root path with a given password.
 */
fun saveRootCerts(zoneCerts: ZoneCerts, rootPath: Path, password: String) {
    val rootStore = X509KeyStore.fromFile(rootPath.resolve("rootstore.jks"), password, createNew = true)
    val doormanStore = X509KeyStore.fromFile(rootPath.resolve("doormanstore.jks"), password, createNew = true)
    val netmapStore = X509KeyStore.fromFile(rootPath.resolve("networkmapstore.jks"), password, createNew = true)

    rootStore.update {
        this.setPrivateKey(X509Utilities.CORDA_ROOT_CA, zoneCerts.root.keyPair.private, listOf(zoneCerts.root.certificate))
    }
    doormanStore.update {
        this.setPrivateKey(X509Utilities.CORDA_INTERMEDIATE_CA, zoneCerts.doorman.keyPair.private, listOf(zoneCerts.root.certificate, zoneCerts.doorman.certificate))
    }
    netmapStore.update {
        this.setPrivateKey("cordanetworkmapca", zoneCerts.networkMap.keyPair.private, listOf(zoneCerts.networkMap.certificate))
    }
}

/**
 * Helper function to save the node certs into keystores under a given root path with a given password.
 */
fun saveNodeCerts(nodeCerts: NodeCerts, zoneCerts: ZoneCerts, rootPath: Path, password: String) {
    val nodeCAStore = X509KeyStore.fromFile(rootPath.resolve("nodekeystore.jks"), password, createNew = true)
    val tlsStore = X509KeyStore.fromFile(rootPath.resolve("sslkeystore.jks"), password, createNew = true)
    val trustStore = X509KeyStore.fromFile(rootPath.resolve("truststore.jks"), password, createNew = true)

    nodeCAStore.update {
        this.setPrivateKey(
                X509Utilities.CORDA_CLIENT_CA,
                nodeCerts.nodeCA.keyPair.private,
                listOf(
                        zoneCerts.root.certificate,
                        zoneCerts.doorman.certificate,
                        nodeCerts.nodeCA.certificate
                )
        )
    }
    tlsStore.update {
        this.setPrivateKey(
                X509Utilities.CORDA_INTERMEDIATE_CA,
                nodeCerts.tls.keyPair.private,
                listOf(
                        zoneCerts.root.certificate,
                        zoneCerts.doorman.certificate,
                        nodeCerts.nodeCA.certificate,
                        nodeCerts.tls.certificate
                )
        )
    }
    trustStore.update {
        this.setCertificate(X509Utilities.CORDA_ROOT_CA, zoneCerts.root.certificate)
    }
}

