package io.imulab.astrea.service.gateway.auth.authn

import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oidc.client.OidcClient
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.sdk.oidc.request.OidcSession
import io.imulab.astrea.sdk.oidc.validation.AuthTimeValidator
import io.imulab.astrea.service.gateway.auth.RoutingContextAttribute
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import java.time.LocalDateTime

/**
 * Skeleton construct for an authentication filter. The main entry point is the [authenticate] method. This method
 * ensures that:
 * - When [shouldFilter] returns false, processing logic will not be executed.
 * - When [tryAuthenticate] throw exception, processing is assumed to have been unable to confirm authentication and will
 * move to the next filter
 * - If authentication context is set after processing, the relation of max_age and auth_time is validated. If such validation
 * fails, processing will also move to next filter.
 */
abstract class AuthenticationFilter {

    private val logger = LoggerFactory.getLogger(AuthenticationFilter::class.java)

    open fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return rc.getAuthentication() == null
    }

    suspend fun authenticate(request: OidcAuthorizeRequest, rc: RoutingContext) {
        if (shouldFilter(request, rc))
            try {
                tryAuthenticate(request, rc)
                validateAuthTime(request, rc)
            } catch (t: Throwable) {
                logger.info("Suppressed authentication filter error <{}>. Assuming failed, moving on to next filter.", t)
                rc.remove<Any>(RoutingContextAttribute.authentication)
            }
    }

    private fun validateAuthTime(request: OidcAuthorizeRequest, rc: RoutingContext) {
        val auth = rc.getAuthentication()
        if (auth != null) {
            AuthTimeValidator.validate(OidcAuthorizeRequest.Builder().also { b ->
                b.client = request.client.assertType()
                b.maxAge = if (request.maxAge > 0) request.maxAge else
                    request.client.assertType<OidcClient>().defaultMaxAge
                b.prompts = request.prompts.toMutableSet()
                b.session = OidcSession(
                    authTime = auth.authTime
                )
            }.build())
        }
    }

    protected abstract suspend fun tryAuthenticate(request: OidcAuthorizeRequest, rc: RoutingContext)
}

/**
 * Data holder for authentication context in routing context.
 */
class Authentication(
    val subject: String,
    val authTime: LocalDateTime? = null,
    val acrValues: List<String> = emptyList()
)

internal fun RoutingContext.getAuthentication(): Authentication? = try {
    get<Authentication>(RoutingContextAttribute.authentication)
} catch (t: Throwable) {
    null
}

internal fun RoutingContext.setAuthentication(auth: Authentication) {
    put(RoutingContextAttribute.authentication, auth)
}