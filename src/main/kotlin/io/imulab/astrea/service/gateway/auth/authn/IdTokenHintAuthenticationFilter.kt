package io.imulab.astrea.service.gateway.auth.authn

import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oauth.token.JwtSigningAlgorithm
import io.imulab.astrea.sdk.oidc.client.OidcClient
import io.imulab.astrea.sdk.oidc.discovery.Discovery
import io.imulab.astrea.sdk.oidc.jwk.JwtVerificationKeyResolver
import io.imulab.astrea.sdk.oidc.jwk.acrValues
import io.imulab.astrea.sdk.oidc.jwk.authTime
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.sdk.oidc.reserved.Prompt
import io.vertx.ext.web.RoutingContext
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.slf4j.LoggerFactory

/**
 * An [AuthenticationFilter] implementation that attempts to resolve authentication from a previously issued
 * id_token via parameter id_token_hint.
 */
class IdTokenHintAuthenticationFilter(
    private val discovery: Discovery,
    private val serviceJwks: JsonWebKeySet
) : AuthenticationFilter() {

    private val logger = LoggerFactory.getLogger(IdTokenHintAuthenticationFilter::class.java)

    override fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return super.shouldFilter(request, rc) &&
                request.idTokenHint.isNotEmpty() &&
                !request.prompts.contains(Prompt.login)
    }

    override suspend fun tryAuthenticate(request: OidcAuthorizeRequest, rc: RoutingContext) {
        val client = request.client.assertType<OidcClient>()
        val idTokenHint = request.idTokenHint

        verifyAndDecodeToken(idTokenHint, client).let { c ->
            rc.setAuthentication(
                Authentication(
                    subject = c.subject,
                    authTime = c.authTime(),
                    acrValues = c.acrValues()
                )
            )

            logger.info("Authentication set via resolved id_token_hint.")
        }
    }

    private fun verifyAndDecodeToken(token: String, client: OidcClient): JwtClaims {
        return when (client.idTokenSignedResponseAlgorithm) {
            JwtSigningAlgorithm.None -> {
                JwtConsumerBuilder()
                    .setRequireJwtId()
                    .setJwsAlgorithmConstraints(client.idTokenSignedResponseAlgorithm.whitelisted())
                    .setSkipVerificationKeyResolutionOnNone()
                    .setDisableRequireSignature()
                    .setExpectedIssuer(discovery.issuer)
                    .build()
                    .processToClaims(token)
            }
            else -> {
                JwtConsumerBuilder()
                    .setRequireJwtId()
                    .setJwsAlgorithmConstraints(client.idTokenSignedResponseAlgorithm.whitelisted())
                    .setVerificationKeyResolver(
                        JwtVerificationKeyResolver(
                            serviceJwks,
                            client.idTokenSignedResponseAlgorithm
                        )
                    )
                    .setExpectedIssuer(discovery.issuer)
                    .build()
                    .processToClaims(token)
            }
        }
    }
}