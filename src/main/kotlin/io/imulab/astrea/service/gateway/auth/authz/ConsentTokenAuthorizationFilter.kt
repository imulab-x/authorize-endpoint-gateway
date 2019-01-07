package io.imulab.astrea.service.gateway.auth.authz

import io.imulab.astrea.sdk.oauth.token.JwtSigningAlgorithm
import io.imulab.astrea.sdk.oidc.jwk.JwtVerificationKeyResolver
import io.imulab.astrea.sdk.oidc.jwk.scopes
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.Params
import io.vertx.ext.web.RoutingContext
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.consumer.JwtConsumerBuilder

class ConsentTokenAuthorizationFilter(
    private val consentProviderJwks: JsonWebKeySet,
    private val consentProviderUrl: String,
    private val serviceName: String
) : AuthorizationFilter() {

    override fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return super.shouldFilter(request, rc) && rc.request().getParam(Params.consentToken) != null
    }

    override suspend fun tryAuthorize(request: OidcAuthorizeRequest, rc: RoutingContext) {
        val consentToken = rc.request().getParam(Params.consentToken)!!

        val claims = JwtConsumerBuilder()
            .also { b ->
                b.setRequireJwtId()
                b.setRequireExpirationTime()
                b.setExpectedIssuer(consentProviderUrl)
                b.setExpectedAudience(serviceName)
                b.setVerificationKeyResolver(JwtVerificationKeyResolver(consentProviderJwks, JwtSigningAlgorithm.RS256))
            }
            .build()
            .processToClaims(consentToken)

        rc.setAuthorization(
            Authorization(
                grantedScopes = claims.scopes()
            )
        )
    }
}