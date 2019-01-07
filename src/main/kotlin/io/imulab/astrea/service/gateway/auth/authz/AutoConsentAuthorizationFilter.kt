package io.imulab.astrea.service.gateway.auth.authz

import com.typesafe.config.Config
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.authz.Authorization
import io.imulab.astrea.service.gateway.auth.authz.AuthorizationFilter
import io.imulab.astrea.service.gateway.auth.authz.setAuthorization
import io.vertx.ext.web.RoutingContext

class AutoConsentAuthorizationFilter(private val config: Config) : AuthorizationFilter() {

    override fun shouldFilter(request: OidcAuthorizeRequest, rc: RoutingContext): Boolean {
        return super.shouldFilter(request, rc) && config.getBoolean("service.consent.auto")
    }

    override suspend fun tryAuthorize(request: OidcAuthorizeRequest, rc: RoutingContext) {
        rc.setAuthorization(
            Authorization(
                grantedScopes = HashSet(request.scopes)
            )
        )
    }
}