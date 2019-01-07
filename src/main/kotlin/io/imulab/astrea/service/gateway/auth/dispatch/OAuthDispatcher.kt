package io.imulab.astrea.service.gateway.auth.dispatch

import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.vertx.ext.web.RoutingContext

/**
 * Service to dispatch an authorize request to the backend flow service, and render response.
 */
interface OAuthDispatcher {

    /**
     * Returns true if the backend service should be able to handle the request. [handle] will be called if the
     * return value is true.
     */
    fun supports(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean

    /**
     * Main method executed to handle the request. Only executed when [supports] returns true. This method must
     * terminate the routing context by calling render methods. It may throw exceptions.
     */
    suspend fun handle(request: OidcAuthorizeRequest, rc: RoutingContext)
}