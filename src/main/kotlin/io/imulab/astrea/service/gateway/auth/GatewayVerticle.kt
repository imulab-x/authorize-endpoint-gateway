package io.imulab.astrea.service.gateway.auth

import com.typesafe.config.Config
import io.imulab.astrea.sdk.oauth.assertType
import io.imulab.astrea.sdk.oauth.error.AccessDenied
import io.imulab.astrea.sdk.oauth.error.ServerError
import io.imulab.astrea.sdk.oauth.request.OAuthRequestProducer
import io.imulab.astrea.sdk.oauth.reserved.Param
import io.imulab.astrea.sdk.oauth.validation.RedirectUriValidator
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequest
import io.imulab.astrea.sdk.oidc.request.OidcRequestForm
import io.imulab.astrea.sdk.oidc.reserved.OidcParam
import io.imulab.astrea.sdk.oidc.reserved.ResponseMode
import io.imulab.astrea.sdk.oidc.validation.*
import io.imulab.astrea.service.gateway.auth.authn.AuthenticationHandler
import io.imulab.astrea.service.gateway.auth.authz.AuthorizationHandler
import io.imulab.astrea.service.gateway.auth.dispatch.OAuthDispatcher
import io.imulab.astrea.service.gateway.auth.lock.ParameterLocker
import io.vertx.core.http.HttpServerOptions
import io.vertx.ext.healthchecks.HealthCheckHandler
import io.vertx.ext.healthchecks.Status
import io.vertx.ext.web.Route
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import io.vertx.kotlin.coroutines.CoroutineVerticle
import io.vertx.kotlin.coroutines.dispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import org.slf4j.LoggerFactory

class GatewayVerticle(
    private val appConfig: Config,
    private val healthCheckHandler: HealthCheckHandler,
    private val requestProducer: OAuthRequestProducer,
    private val authenticationHandler: AuthenticationHandler,
    private val authorizationHandler: AuthorizationHandler,
    private val parameterLocker: ParameterLocker,
    private val supportValidator: SupportValidator,
    private val dispatchers: List<OAuthDispatcher>
) : CoroutineVerticle() {

    private val logger = LoggerFactory.getLogger(GatewayVerticle::class.java)

    override suspend fun start() {
        val router = Router.router(vertx)

        router.get("/")
            .suspendedOAuthHandler { rc ->
                /**
                 * Lock incoming parameters. If param_lock is present, check parameter integrity.
                 */
                parameterLocker.hashParameters(rc)
                try {
                    parameterLocker.verifyParameterLock(rc)
                } catch (e: Exception) {
                    logger.error("Error while verifying parameter lock.", e)
                    throw AccessDenied.byServer("parameter lock is potentially tempered.")
                }

                /**
                 * Parse request parameters and produce the request.
                 */
                val form = OidcRequestForm(
                    rc.request().params().entries().groupBy(
                        keySelector = { e -> e.key },
                        valueTransform = { e -> e.value }
                    ).toMutableMap()
                )
                val request = requestProducer.produce(form).assertType<OidcAuthorizeRequest>().also {
                    rc.setOidcAuthorizeRequest(it)
                }

                /**
                 * Perform preliminary validation.
                 *
                 * Special case: validate redirect_uri and response_mode first. If they are valid, set them on context,
                 * so any errors after can be rendered properly
                 */
                RedirectUriValidator.validate(request)
                rc.put(
                    Param.redirectUri,
                    request.redirectUri.defaultOnEmpty(request.client.redirectUris.first())
                )
                ResponseModeValidator.validate(request)
                rc.put(
                    OidcParam.responseMode,
                    request.responseMode.defaultOnEmpty(ResponseMode.query)
                )
                listOf(MaxAgeValidator, PromptValidator, DisplayValidator, supportValidator).forEach { v ->
                    v.validate(request)
                }

                rc.next()
            }
            .suspendedOAuthHandler { rc ->
                /**
                 * Resolve authentication context, and acquire user authorization.
                 */
                authenticationHandler.authenticateOrRedirect(rc)
                authorizationHandler.authorizeOrRedirect(rc)

                rc.next()
            }
            .suspendedOAuthHandler { rc ->
                /**
                 * Find a handler that supports processing the request and dispatch it.
                 */
                val request = rc.getOidcAuthorizeRequest()!!
                val dispatcher = dispatchers.find { it.supports(request, rc) }
                    ?: throw ServerError.internal("Cannot find proper handler for request.")
                dispatcher.handle(request, rc)
            }
        router.get("/health").handler(healthCheckHandler)

        vertx.createHttpServer(HttpServerOptions().apply {
            port = appConfig.getInt("service.port")
        }).requestHandler(router).listen()

        healthCheckHandler.register("AuthorizeEndpointGatewayAPI") { h -> h.complete(Status.OK()) }
    }

    private fun Route.suspendedOAuthHandler(block: suspend (RoutingContext) -> Unit): Route {
        handler { rc ->
            CoroutineScope(rc.vertx().dispatcher()).async {
                block(rc)
            }.invokeOnCompletion { e ->
                if (e != null)
                    ResponseRenderer.render(e, rc)
            }
        }
        return this
    }

    private fun String.defaultOnEmpty(default: String): String = if (this.isNotEmpty()) this else default
}

private const val requestKey = "OidcAuthorizeRequest"

internal fun RoutingContext.getOidcAuthorizeRequest(): OidcAuthorizeRequest? =
    get(requestKey)

internal fun RoutingContext.setOidcAuthorizeRequest(r: OidcAuthorizeRequest) {
    put(requestKey, r)
}

internal class RedirectionSignal(val url: String) : RuntimeException()