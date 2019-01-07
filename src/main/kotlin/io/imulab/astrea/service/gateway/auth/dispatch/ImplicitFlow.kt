package io.imulab.astrea.service.gateway.auth.dispatch

import io.grpc.Channel
import io.imulab.astrea.sdk.commons.flow.implicit.ImplicitFlowServiceGrpc
import io.imulab.astrea.sdk.commons.flow.implicit.ImplicitTokenResponse
import io.imulab.astrea.sdk.commons.toOAuthException
import io.imulab.astrea.sdk.flow.implicit.toImplicitTokenRequest
import io.imulab.astrea.sdk.flow.implicit.toOidcAuthorizeEndpointResponse
import io.imulab.astrea.sdk.oauth.exactly
import io.imulab.astrea.sdk.oauth.reserved.ResponseType.token
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.sdk.oidc.reserved.ResponseType.idToken
import io.imulab.astrea.service.gateway.auth.ResponseRenderer
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory

class ImplicitFlow(channel: Channel) : OAuthDispatcher {

    private val logger = LoggerFactory.getLogger(ImplicitFlow::class.java)

    private val stub = ImplicitFlowServiceGrpc.newBlockingStub(channel)

    override fun supports(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return when (request.responseTypes.size) {
            1 -> request.responseTypes.exactly(token) || request.responseTypes.exactly(idToken)
            2 -> request.responseTypes.containsAll(listOf(token, idToken))
            else -> false
        }
    }

    override suspend fun handle(request: OidcAuthorizeRequest, rc: RoutingContext) {
        val response : ImplicitTokenResponse = try {
            stub.authorize(request.toImplicitTokenRequest())
        } catch (e: Exception) {
            logger.error("Error calling implicit flow service.", e)
            throw e
        }

        if (response.success) {
            ResponseRenderer.render(response.toOidcAuthorizeEndpointResponse(), rc)
        } else {
            throw response.failure.toOAuthException()
        }
    }
}