package io.imulab.astrea.service.gateway.auth.authn

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

class AuthenticationHandler(
    private val loginProviderUrl: String,
    private val filters: List<AuthenticationFilter>,
    private val locker: ParameterLocker,
    private val subjectObfuscation: SubjectObfuscation
) {

    suspend fun authenticateOrRedirect(rc: RoutingContext) {
        val request = rc.getOidcAuthorizeRequest()!!

        /**
         * Let authentication filters work their magic to try
         * establish an authentication context.
         */
        filters.forEach { f ->
            f.authenticate(request, rc)
        }

        /**
         * Transfer established authentication context to request session,
         * and continue processing.
         */
        val auth = rc.getAuthentication()
        if (auth != null) {
            request.session.assertType<OidcSession>().apply {
                subject = auth.subject
                obfuscatedSubject = subjectObfuscation.obfuscate(auth.subject, request.client.assertType())
                authTime = auth.authTime
                acrValues.addAll(auth.acrValues)
            }
            return
        }

        /**
         * Fail if:
         * - Login provider responded (re-entry scenario), but still no authentication
         * - prompt=none, and unable to resolve authentication
         */
        when {
            locker.hasVisitedAuthenticationBefore(rc) ->
                throw AccessDenied.byServer("Server was not able to establish user identity.")
            request.prompts.contains(Prompt.none) ->
                throw AccessDenied.noAuthenticationOnNonePrompt()
        }

        /**
         * Throw special redirect signal, so route handlers can redirect user to external provider.
         */
        val url = HttpUrl.parse(loginProviderUrl)!!
            .newBuilder()
            .also { b ->
                rc.request().params().forEach { p -> b.addQueryParameter(p.key, p.value) }
                b.addQueryParameter(Params.parameterLock, locker.createLockForAuthenticationStage(rc))
            }
            .build()
            .toString()
        throw RedirectionSignal(url)
    }
}