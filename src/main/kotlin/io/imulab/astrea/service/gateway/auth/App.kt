package io.imulab.astrea.service.gateway.auth

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import io.grpc.ManagedChannelBuilder
import io.imulab.astrea.sdk.client.RemoteClientLookupService
import io.imulab.astrea.sdk.commons.doNotCall
import io.imulab.astrea.sdk.discovery.RemoteDiscoveryService
import io.imulab.astrea.sdk.discovery.SampleDiscovery
import io.imulab.astrea.sdk.event.ClientEvents
import io.imulab.astrea.sdk.oauth.client.ClientLookup
import io.imulab.astrea.sdk.oauth.client.OAuthClient
import io.imulab.astrea.sdk.oauth.request.OAuthRequestProducer
import io.imulab.astrea.sdk.oidc.discovery.Discovery
import io.imulab.astrea.sdk.oidc.discovery.OidcContext
import io.imulab.astrea.sdk.oidc.request.OidcAuthorizeRequestProducer
import io.imulab.astrea.sdk.oidc.request.RequestObjectAwareOidcAuthorizeRequestProducer
import io.imulab.astrea.sdk.oidc.validation.OidcResponseTypeValidator
import io.imulab.astrea.sdk.oidc.validation.SupportValidator
import io.imulab.astrea.service.gateway.auth.authn.*
import io.imulab.astrea.service.gateway.auth.authz.AuthorizationHandler
import io.imulab.astrea.service.gateway.auth.authz.AutoConsentAuthorizationFilter
import io.imulab.astrea.service.gateway.auth.authz.ConsentTokenAuthorizationFilter
import io.imulab.astrea.service.gateway.auth.dispatch.AuthorizeCodeFlowAuthorizeLeg
import io.imulab.astrea.service.gateway.auth.dispatch.ImplicitFlow
import io.imulab.astrea.service.gateway.auth.lock.ParameterLocker
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.ext.healthchecks.HealthCheckHandler
import io.vertx.kotlin.coroutines.awaitResult
import kotlinx.coroutines.runBlocking
import org.jose4j.jwk.JsonWebKeySet
import org.jose4j.keys.AesKey
import org.kodein.di.Kodein
import org.kodein.di.generic.bind
import org.kodein.di.generic.eagerSingleton
import org.kodein.di.generic.instance
import org.kodein.di.generic.singleton
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.*

private val logger: Logger = LoggerFactory.getLogger("io.imulab.astrea.service.gateway.auth.AppKt")

suspend fun main(args: Array<String>) {
    val vertx = Vertx.vertx()
    val config = ConfigFactory.load()

    val components = App(vertx, config).bootstrap()
    val gateway by components.instance<GatewayVerticle>()

    try {
        val deploymentId = awaitResult<String> { vertx.deployVerticle(gateway, it) }
        logger.info("Authorize endpoint gateway service successfully deployed with id {}", deploymentId)
    } catch (e: Exception) {
        logger.error("Authorize endpoint gateway service encountered error during deployment.", e)
    }
}

@Suppress("MemberVisibilityCanBePrivate")
open class App(private val vertx: Vertx, private val config: Config) {

    open fun bootstrap(): Kodein {
        return Kodein {
            importOnce(discovery)
            importOnce(client)
            importOnce(authorizeCodeFlow)
            importOnce(implicitFlow)
            importOnce(app)

            bind<GatewayVerticle>() with singleton {
                GatewayVerticle(
                    appConfig = config,
                    healthCheckHandler = instance(),
                    requestProducer = instance(),
                    authenticationHandler = instance(),
                    authorizationHandler = instance(),
                    parameterLocker = instance(),
                    supportValidator = instance(),
                    dispatchers = listOf(
                        instance<AuthorizeCodeFlowAuthorizeLeg>(),
                        instance<ImplicitFlow>()
                    )
                )
            }
        }
    }

    val app = Kodein.Module("app") {
        bind<HealthCheckHandler>() with singleton { HealthCheckHandler.create(vertx) }

        bind<OAuthRequestProducer>() with singleton {
            RequestObjectAwareOidcAuthorizeRequestProducer(
                discovery = instance(),
                requestStrategy = LocalResolveRequestStrategy(
                    context = ServiceContext(config, instance())
                ),
                firstPassProducer = OidcAuthorizeRequestProducer(
                    lookup = instance(),
                    claimConverter = JacksonClaimConverter,
                    responseTypeValidator = OidcResponseTypeValidator
                )
            )
        }

        bind<ParameterLocker>() with singleton {
            ParameterLocker(
                serviceName = config.getString("service.name"),
                lockKey = AesKey(Base64.getDecoder().decode(config.getString("service.paramLockKey")))
            )
        }

        bind<SupportValidator>() with singleton { SupportValidator(instance()) }

        bind<AuthenticationHandler>() with singleton {
            AuthenticationHandler(
                loginProviderUrl = config.getString("login.url"),
                filters = listOf(
                    instance<LoginTokenAuthenticationFilter>(),
                    instance<IdTokenHintAuthenticationFilter>(),
                    instance<AutoLoginAuthenticationFilter>()
                ),
                locker = instance(),
                subjectObfuscation = SubjectObfuscation(
                    Base64.getDecoder().decode(config.getString("service.pairwiseSalt"))
                )
            )
        }

        bind<LoginTokenAuthenticationFilter>() with singleton {
            LoginTokenAuthenticationFilter(
                loginProviderUrl = config.getString("login.url"),
                serviceName = config.getString("service.name"),
                loginProviderJwks = JsonWebKeySet(config.getString("login.jwks"))
            )
        }

        bind<IdTokenHintAuthenticationFilter>() with singleton {
            IdTokenHintAuthenticationFilter(instance(), JsonWebKeySet(config.getString("service.jwks")))
        }

        bind<AutoLoginAuthenticationFilter>() with singleton {
            AutoLoginAuthenticationFilter(config = config)
        }

        bind<ConsentTokenAuthorizationFilter>() with singleton {
            ConsentTokenAuthorizationFilter(
                consentProviderUrl = config.getString("consent.url"),
                serviceName = config.getString("service.name"),
                consentProviderJwks = JsonWebKeySet(config.getString("consent.jwks"))
            )
        }

        bind<AutoConsentAuthorizationFilter>() with singleton {
            AutoConsentAuthorizationFilter(config = config)
        }

        bind<AuthorizationHandler>() with singleton {
            AuthorizationHandler(
                consentProviderUrl = config.getString("consent.url"),
                locker = instance(),
                filters = listOf(
                    instance<ConsentTokenAuthorizationFilter>(),
                    instance<AutoConsentAuthorizationFilter>()
                )
            )
        }
    }

    val authorizeCodeFlow = Kodein.Module("authorizeCodeFlow") {
        bind<AuthorizeCodeFlowAuthorizeLeg>() with singleton {
            AuthorizeCodeFlowAuthorizeLeg(
                ManagedChannelBuilder.forAddress(
                    config.getString("authorizeCodeFlow.host"),
                    config.getInt("authorizeCodeFlow.port")
                )
                    .enableRetry()
                    .maxRetryAttempts(10)
                    .usePlaintext()
                    .build()
            )
        }
    }

    val implicitFlow = Kodein.Module("implicitFlow") {
        bind<ImplicitFlow>() with singleton {
            ImplicitFlow(
                ManagedChannelBuilder.forAddress(
                    config.getString("implicitFlow.host"),
                    config.getInt("implicitFlow.port")
                )
                    .enableRetry()
                    .maxRetryAttempts(10)
                    .usePlaintext()
                    .build()
            )
        }
    }

    val client = Kodein.Module("client") {

        bind<Cache<String, OAuthClient>>() with singleton {
            val cache = Caffeine.newBuilder()
                .maximumSize(500)
                .build<String, OAuthClient>()

            vertx.eventBus().consumer<JsonObject>(ClientEvents.updateClientEvent) { m ->
                cache.invalidate(m.body().getString("id"))
            }
            vertx.eventBus().consumer<JsonObject>(ClientEvents.deleteClientEvent) { m ->
                cache.invalidate(m.body().getString("id"))
            }

            cache
        }

        bind<ClientLookup>() with singleton {
            RemoteClientLookupService(
                channel = ManagedChannelBuilder.forAddress(
                    config.getString("client.host"),
                    config.getInt("client.port")
                ).enableRetry().maxRetryAttempts(10).usePlaintext().build(),
                cache = instance()
            )
        }
    }

    val discovery = Kodein.Module("discovery") {
        bind<Discovery>() with eagerSingleton {
            if (config.getBoolean("discovery.useSample")) {
                logger.info("Using default discovery instead of remote.")
                SampleDiscovery.default()
            } else {
                val channel = ManagedChannelBuilder.forAddress(
                    config.getString("discovery.host"),
                    config.getInt("discovery.port")
                ).enableRetry().maxRetryAttempts(10).usePlaintext().build()

                runBlocking {
                    RemoteDiscoveryService(channel).getDiscovery()
                }.also { logger.info("Acquired discovery remote remote") }
            }
        }
    }
}