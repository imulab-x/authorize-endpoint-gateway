package io.imulab.astrea.service.gateway.auth.authn

import io.imulab.astrea.sdk.oauth.error.InvalidRequest
import io.imulab.astrea.sdk.oidc.client.OidcClient
import io.imulab.astrea.sdk.oidc.reserved.SubjectType
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class SubjectObfuscation(private val pairwiseSalt: ByteArray) {

    private val sha256: MessageDigest = MessageDigest.getInstance("SHA-256")

    init {
        assert(pairwiseSalt.isNotEmpty())
    }

    fun obfuscate(subject: String, client: OidcClient): String {
        return when (client.subjectType) {
            SubjectType.public -> subject
            SubjectType.pairwise -> {
                ((client.effectiveSectorIdentifier() + subject).toByteArray() + pairwiseSalt)
                    .let { sha256.digest(it) }
                    .toString(StandardCharsets.UTF_8)
            }
            else -> throw IllegalStateException("Invalid subject type ${client.subjectType}.")
        }
    }

    private fun OidcClient.effectiveSectorIdentifier(): String {
        if (sectorIdentifierUri.isNotBlank())
            return URI(sectorIdentifierUri).host

        with(redirectUris.map { URI(it).host }.toSet()) {
            if (size == 0 || size > 1)
                throw InvalidRequest.unmet("Client must register redirect_uris with unique host when sector_identifier_uri is not set.")
            else
                return this.first()
        }
    }
}