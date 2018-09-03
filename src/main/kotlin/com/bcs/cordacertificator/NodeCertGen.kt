package com.bcs.cordacertificator

import net.corda.core.crypto.Crypto.RSA_SHA256
import net.corda.core.crypto.Crypto.generateKeyPair
import net.corda.core.identity.CordaX500Name
import net.corda.core.internal.x500Name
import net.corda.nodeapi.internal.crypto.CertificateAndKeyPair
import net.corda.nodeapi.internal.crypto.CertificateType
import net.corda.nodeapi.internal.crypto.X509Utilities
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralSubtree
import org.bouncycastle.asn1.x509.NameConstraints
import org.bouncycastle.jcajce.provider.asymmetric.RSA

fun generateNodeCerts(nodeName: CordaX500Name, zoneCerts: ZoneCerts): NodeCerts{
    val nameConstraints = NameConstraints(arrayOf(GeneralSubtree(GeneralName(GeneralName.directoryName, nodeName.x500Name))), arrayOf())
    val nodeCAKP = generateKeyPair(RSA_SHA256)
    val tlsKP = generateKeyPair(RSA_SHA256)

    val nodeCACert = X509Utilities.createCertificate(
            CertificateType.NODE_CA,
            zoneCerts.doorman.certificate,
            zoneCerts.doorman.keyPair,
            nodeName.x500Principal,
            nodeCAKP.public,
            nameConstraints = nameConstraints
    )
    val tlsCert = X509Utilities.createCertificate(
            CertificateType.TLS,
            nodeCACert,
            nodeCAKP,
            nodeName.x500Principal,
            tlsKP.public
    )

    val nodeCACKP = CertificateAndKeyPair(nodeCACert, nodeCAKP)
    val tlsCKP = CertificateAndKeyPair(tlsCert, tlsKP)

    return NodeCerts(nodeCACKP, tlsCKP)
}

data class NodeCerts(val nodeCA: CertificateAndKeyPair, val tls: CertificateAndKeyPair)