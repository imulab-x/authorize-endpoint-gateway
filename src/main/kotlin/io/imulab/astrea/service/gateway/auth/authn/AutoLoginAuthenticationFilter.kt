package io.imulab.astrea.service.gateway.auth.authn

import com.typesafe.config.Config
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.authn.Authentication
import io.imulab.astrea.service.gateway.auth.authn.AuthenticationFilter
import io.imulab.astrea.service.gateway.auth.authn.setAuthentication
import io.vertx.ext.web.RoutingContext
import java.time.LocalDateTime

class AutoLoginAuthenticationFilter(
    private val config: Config,
    private val subject: String = "foo@bar.com"
) : AuthenticationFilter() {

    override fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return super.shouldFilter(request, rc) && config.getBoolean("service.login.auto")
    }

    override suspend fun tryAuthenticate(request: OidcAuthorizeRequest, rc: RoutingContext) {
        rc.setAuthentication(
            Authentication(
                subject = subject,
                authTime = LocalDateTime.now().minusSeconds(5),
                acrValues = listOf("0")
            )
        )
    }
}