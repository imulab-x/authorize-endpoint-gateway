package io.imulab.astrea.service.gateway.auth.authz

import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.RoutingContextAttribute
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory

abstract class AuthorizationFilter {

    private val logger = LoggerFactory.getLogger(AuthorizationFilter::class.java)

    open fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return rc.getAuthorization() == null
    }

    suspend fun authorize(request: OidcAuthorizeRequest, rc: RoutingContext) {
        if (shouldFilter(request, rc)) {
            try {
                tryAuthorize(request, rc)
            } catch (t: Throwable) {
                logger.info("Suppressed authorization filter error <{}>. Assuming failed, moving on to next filter.", t)
                rc.remove<Any>(RoutingContextAttribute.authorization)
            }
        }
    }

    protected abstract suspend fun tryAuthorize(request: OidcAuthorizeRequest, rc: RoutingContext)
}

/**
 * Data holder for authentication context in routing context.
 */
class Authorization(
    val grantedScopes: Set<String>,
    val idTokenClaims: Map<String, Any> = emptyMap(),
    val accessTokenClaims: Map<String, Any> = emptyMap()
)

internal fun RoutingContext.getAuthorization(): Authorization? = try {
    get<Authorization>(RoutingContextAttribute.authorization)
} catch (t: Throwable) {
    null
}

internal fun RoutingContext.setAuthorization(auth: Authorization) {
    put(RoutingContextAttribute.authorization, auth)
}