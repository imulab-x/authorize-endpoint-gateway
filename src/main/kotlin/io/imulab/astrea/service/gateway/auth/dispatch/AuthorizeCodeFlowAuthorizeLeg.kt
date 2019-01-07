package io.imulab.astrea.service.gateway.auth.dispatch

import io.grpc.Channel
import io.imulab.astrea.sdk.commons.flow.code.AuthorizeCodeFlowServiceGrpc
import io.imulab.astrea.sdk.commons.toOAuthException
import io.imulab.astrea.sdk.flow.code.toAuthorizeEndpointResponse
import io.imulab.astrea.sdk.flow.code.toCodeRequest
import io.imulab.astrea.sdk.oauth.exactly
import io.imulab.astrea.sdk.oauth.reserved.ResponseType
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.ResponseRenderer
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory

class AuthorizeCodeFlowAuthorizeLeg(channel: Channel) : OAuthDispatcher {

    private val logger = LoggerFactory.getLogger(AuthorizeCodeFlowAuthorizeLeg::class.java)

    private val stub = AuthorizeCodeFlowServiceGrpc.newBlockingStub(channel)

    override fun supports(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return request.responseTypes.exactly(ResponseType.code)
    }

    override suspend fun handle(request: OidcAuthorizeRequest, rc: RoutingContext) {
        val response = try {
            stub.authorize(request.toCodeRequest())
        } catch (e: Exception) {
            logger.error("Error calling authorize code flow service.", e)
            throw e
        }

        if (response.success) {
            ResponseRenderer.render(response.toAuthorizeEndpointResponse(), rc)
        } else {
            throw response.failure.toOAuthException()
        }
    }
}