package io.imulab.astrea.service.gateway.auth.authz

import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oauth.error.AccessDenied
import io.imulab.astrea.sdk.oidc.request.OidcSession
import io.imulab.astrea.sdk.oidc.reserved.Prompt
import io.imulab.astrea.service.gateway.auth.Params
import io.imulab.astrea.service.gateway.auth.RedirectionSignal
import io.imulab.astrea.service.gateway.auth.getOidcAuthorizeRequest
import io.imulab.astrea.service.gateway.auth.lock.ParameterLocker
import io.vertx.ext.web.RoutingContext
import okhttp3.HttpUrl

class AuthorizationHandler(
    private val consentProviderUrl: String,
    private val filters: List<AuthorizationFilter>,
    private val locker: ParameterLocker
) {

    suspend fun authorizeOrRedirect(rc: RoutingContext) {
        val request = rc.getOidcAuthorizeRequest()!!

        /**
         * Let filters work their magic to acquire user authorization
         */
        filters.forEach { f ->
            f.authorize(request, rc)
        }

        /**
         * If authorization is acquired, populate session fields and return.
         */
        val auth = rc.getAuthorization()
        if (auth != null) {
            request.session.assertType<OidcSession>().apply {
                grantedScopes.addAll(auth.grantedScopes)
                accessTokenClaims.putAll(auth.accessTokenClaims)
                idTokenClaims.putAll(auth.idTokenClaims)
            }
            return
        }

        /**
         * If authorization cannot be acquired, fail if:
         * - Redirection to consent provider already happened (i.e. this is re-entry).
         * - prompt=none, we cannot redirect to ask for user interaction.
         */
        when {
            locker.hasVisitedAuthorizationBefore(rc) ->
                throw AccessDenied.byServer("Server was not able to acquire user consent.")
            request.prompts.contains(Prompt.none) ->
                throw AccessDenied.noAuthorizationOnNonePrompt()
        }

        /**
         * Redirect to consent provider for explicit user authorization.
         */
        val url = HttpUrl.parse(consentProviderUrl)!!
            .newBuilder()
            .also { b ->
                rc.request().params().forEach { p -> b.addQueryParameter(p.key, p.value) }
                b.addQueryParameter(Params.parameterLock, locker.createLockForAuthorizationStage(rc))
            }
            .build()
            .toString()
        throw RedirectionSignal(url)
    }
}