package io.imulab.astrea.service.gateway.auth.authn

import io.imulab.astrea.sdk.oauth.token.JwtSigningAlgorithm
import io.imulab.astrea.sdk.oidc.jwk.JwtVerificationKeyResolver
import io.imulab.astrea.sdk.oidc.jwk.acrValues
import io.imulab.astrea.sdk.oidc.jwk.authTime
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.Params
import io.vertx.ext.web.RoutingContext
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.consumer.JwtConsumerBuilder

/**
 * An implementation of [AuthenticationFilter] that attempts to resolve authentication from login token.
 */
class LoginTokenAuthenticationFilter(
    private val loginProviderJwks: JsonWebKeySet,
    private val loginProviderUrl: String,
    private val serviceName: String
) : AuthenticationFilter() {

    override fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return super.shouldFilter(request, rc) && rc.request().getParam(Params.loginToken) != null
    }

    override suspend fun tryAuthenticate(request: OidcAuthorizeRequest, rc: RoutingContext) {
        val loginToken = rc.request().getParam(Params.loginToken)!!

        val claims = JwtConsumerBuilder()
            .also { b ->
                b.setRequireJwtId()
                b.setRequireExpirationTime()
                b.setExpectedIssuer(loginProviderUrl)
                b.setExpectedAudience(serviceName)
                b.setVerificationKeyResolver(JwtVerificationKeyResolver(loginProviderJwks, JwtSigningAlgorithm.RS256))
            }
            .build()
            .processToClaims(loginToken)

        if (claims.subject.isEmpty())
            return

        rc.setAuthentication(
            Authentication(
                subject = claims.subject,
                authTime = claims.authTime(),
                acrValues = claims.acrValues()
            )
        )
    }
}