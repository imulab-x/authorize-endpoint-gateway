package io.imulab.astrea.service.gateway.auth

import com.fasterxml.jackson.module.kotlin.readValue
import com.typesafe.config.Config
import io.imulab.astrea.sdk.client.AstreaClient
import io.imulab.astrea.sdk.commons.doNotCall
import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oauth.error.InvalidRequest
import io.imulab.astrea.sdk.oauth.error.ServerError
import io.imulab.astrea.sdk.oidc.claim.ClaimConverter
import io.imulab.astrea.sdk.oidc.claim.Claims
import io.imulab.astrea.sdk.oidc.client.OidcClient
import io.imulab.astrea.sdk.oidc.discovery.Discovery
import io.imulab.astrea.sdk.oidc.discovery.OidcContext
import io.imulab.astrea.sdk.oidc.jwk.JsonWebKeySetRepository
import io.imulab.astrea.sdk.oidc.jwk.JsonWebKeySetStrategy
import io.imulab.astrea.sdk.oidc.request.CachedRequest
import io.imulab.astrea.sdk.oidc.request.CachedRequestRepository
import io.imulab.astrea.sdk.oidc.request.RequestStrategy
import io.imulab.astrea.sdk.oidc.reserved.OidcParam
import io.imulab.astrea.sdk.oidc.spi.HttpResponse
import io.imulab.astrea.sdk.oidc.spi.SimpleHttpClient
import io.vertx.core.json.Json
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.jwt.JwtClaims
import java.time.Duration
import java.util.LinkedHashMap

object RoutingContextAttribute {
    const val authentication = "authentication"
    const val authorization = "authorization"
    const val parameterHash = "param_hash"
    const val verifiedParameterLock = "verified_param_lock"
}

object Stage {
    const val name = "stage"
    const val authentication = 1
    const val authorization = 2
}

object Params {
    const val parameterLock = "param_lock"
    const val loginToken = "login_token"
    const val consentToken = "consent_token"
}

/**
 * Converter for `claim` parameter using Vertx's main jackson object mapper.
 */
object JacksonClaimConverter: ClaimConverter {
    override fun fromJson(json: String): Claims {
        return try {
            Claims(
                Json.mapper.readValue<LinkedHashMap<String, Any>>(
                    json
                )
            )
        } catch (e: Exception) {
            throw InvalidRequest.invalid(OidcParam.claims)
        }
    }
}

private object DoNotCallHttpClient : SimpleHttpClient {
    override suspend fun get(url: String): HttpResponse = doNotCall()
}

/**
 * Resolve the client jwks using [OidcClient.jwks]. Remote client service is supposed to have resolved the jwks_uri
 * into jwks. Hence, there is not need to perform another http call.
 */
object LocalJsonWebKeySetStrategy : JsonWebKeySetStrategy(
    httpClient = DoNotCallHttpClient,
    jsonWebKeySetRepository = object : JsonWebKeySetRepository {
        override suspend fun getClientJsonWebKeySet(jwksUri: String): JsonWebKeySet? = doNotCall()
        override suspend fun getServerJsonWebKeySet(): JsonWebKeySet = doNotCall()
        override suspend fun writeClientJsonWebKeySet(jwksUri: String, keySet: JsonWebKeySet) = doNotCall()
    }
) {
    override suspend fun resolveKeySet(client: OidcClient): JsonWebKeySet {
        return if (client.jwks.isNotEmpty()) JsonWebKeySet(client.jwks) else JsonWebKeySet()
    }
}

/**
 * Request strategy to resolve the request_uri using [AstreaClient.requests]. Remote client service is supposed to have
 * resolved the request_uri into requests. Hence, there is no need to perform another http call.
 */
class LocalResolveRequestStrategy(context: OidcContext) : RequestStrategy(
    repository = object : CachedRequestRepository {
        override suspend fun evict(requestUri: String) = doNotCall()
        override suspend fun find(requestUri: String): CachedRequest? = doNotCall()
        override suspend fun write(request: CachedRequest) = doNotCall()
    },
    jsonWebKeySetStrategy = LocalJsonWebKeySetStrategy,
    httpClient = DoNotCallHttpClient,
    requestCacheLifespan = Duration.ZERO,
    serverContext = context
) {

    override suspend fun doResolveRequest(request: String, requestUri: String, client: OidcClient): JwtClaims {
        if (request.isNotEmpty()) {
            check(requestUri.isEmpty()) {
                "request and request_uri cannot be used at the same time."
            }

            return processRequest(request, client)
        }

        if (requestUri.isNotEmpty()) {
            if (!client.requestUris.contains(requestUri))
                throw io.imulab.astrea.sdk.oidc.error.InvalidRequestUri.rouge()
            else if (requestUri.length > 512)
                throw io.imulab.astrea.sdk.oidc.error.InvalidRequestUri.tooLong()

            val resolvedRequest = client.assertType<AstreaClient>().requests[requestUri]
                ?: throw ServerError.internal("Registered request_uri was not resolved.")

            return processRequest(
                request = resolvedRequest,
                client = client
            )
        }

        return JwtClaims()
    }
}

/**
 * An [OidcContext] implementation that only cares about [OidcContext.masterJsonWebKeySet] and
 * [OidcContext.issuerUrl].
 */
class ServiceContext(config: Config, discovery: Discovery) : OidcContext, Discovery by discovery {
    override val authorizeEndpointUrl: String = authorizationEndpoint
    override val tokenEndpointUrl: String = tokenEndpoint
    override val issuerUrl: String = issuer
    override val masterJsonWebKeySet: JsonWebKeySet = JsonWebKeySet(config.getString("service.jwks"))

    override val accessTokenLifespan: Duration by lazy { doNotCall() }
    override val authorizeCodeLifespan: Duration by lazy { doNotCall() }
    override val defaultTokenEndpointAuthenticationMethod: String by lazy { doNotCall() }
    override val idTokenLifespan: Duration by lazy { doNotCall() }
    override val nonceEntropy: Int by lazy { doNotCall() }
    override val refreshTokenLifespan: Duration by lazy { doNotCall() }
    override val stateEntropy: Int by lazy { doNotCall() }

    override fun validate() = doNotCall()
}