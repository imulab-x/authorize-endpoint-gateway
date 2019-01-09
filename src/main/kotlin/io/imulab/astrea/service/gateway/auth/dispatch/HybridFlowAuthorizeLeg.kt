package io.imulab.astrea.service.gateway.auth.dispatch

import io.imulab.astrea.sdk.flow.hybrid.HybridFlowCodeLegService
import io.imulab.astrea.sdk.oauth.reserved.ResponseType
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.ResponseRenderer
import io.vertx.ext.web.RoutingContext

class HybridFlowAuthorizeLeg(
    private val service: HybridFlowCodeLegService
) : OAuthDispatcher {

    override fun supports(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return when (request.responseTypes.size) {
            2 -> request.responseTypes.containsAll(listOf(
                ResponseType.code,
                ResponseType.token
            )) || request.responseTypes.containsAll(listOf(
                ResponseType.code,
                io.imulab.astrea.sdk.oidc.reserved.ResponseType.idToken
            ))
            3 -> request.responseTypes.containsAll(listOf(
                ResponseType.code,
                ResponseType.token,
                io.imulab.astrea.sdk.oidc.reserved.ResponseType.idToken
            ))
            else -> false
        }
    }

    override suspend fun handle(request: OidcAuthorizeRequest, rc: RoutingContext) {
        ResponseRenderer.render(service.authorize(request), rc)
    }
}