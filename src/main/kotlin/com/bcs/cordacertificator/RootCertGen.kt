package com.bcs.cordacertificator

import net.corda.core.crypto.Crypto.RSA_SHA256
import net.corda.core.crypto.Crypto.generateKeyPair
import net.corda.core.identity.CordaX500Name
import net.corda.nodeapi.internal.crypto.CertificateAndKeyPair
import net.corda.nodeapi.internal.crypto.CertificateType
import net.corda.nodeapi.internal.crypto.X509Utilities

/**
 * Generates a new root zone, given root names.
 */
fun generateRootZone(
        rootName: CordaX500Name,
        doormanName: CordaX500Name,
        netmapName: CordaX500Name
): ZoneCerts {
    val rootKP = generateKeyPair(RSA_SHA256)
    val rootCert = X509Utilities.createSelfSignedCACertificate(rootName.x500Principal, rootKP)
    val rootCKP = CertificateAndKeyPair(rootCert, rootKP)

    return generateRootZone(rootCKP, doormanName, netmapName)
}

/**
 * Generates a new root zone, given a root CA cert.
 */
fun generateRootZone(
        rootCKP: CertificateAndKeyPair,
        doormanName: CordaX500Name,
        netmapName: CordaX500Name
): ZoneCerts {
    val doormanKP = generateKeyPair(RSA_SHA256)
    val netmapKP = generateKeyPair(RSA_SHA256)

    val doormanCert = X509Utilities.createCertificate(
            CertificateType.INTERMEDIATE_CA,
            rootCKP.certificate,
            rootCKP.keyPair,
            doormanName.x500Principal,
            doormanKP.public
    )
    val netmapCert = X509Utilities.createCertificate(
            CertificateType.NETWORK_MAP,
            rootCKP.certificate,
            rootCKP.keyPair,
            netmapName.x500Principal,
            netmapKP.public
    )

    val doormanCKP = CertificateAndKeyPair(doormanCert, doormanKP)
    val netmapCKP = CertificateAndKeyPair(netmapCert, netmapKP)

    return ZoneCerts(rootCKP, doormanCKP, netmapCKP)
}

data class ZoneCerts(val root: CertificateAndKeyPair, val doorman: CertificateAndKeyPair, val networkMap: CertificateAndKeyPair)
