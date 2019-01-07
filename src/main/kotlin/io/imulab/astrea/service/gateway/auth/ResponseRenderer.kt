package io.imulab.astrea.service.gateway.auth

import io.imulab.astrea.sdk.oauth.error.OAuthException
import io.imulab.astrea.sdk.oauth.error.ServerError
import io.imulab.astrea.sdk.oauth.reserved.Param
import io.imulab.astrea.sdk.oauth.response.AuthorizeEndpointResponse
import io.imulab.astrea.sdk.oidc.reserved.OidcParam
import io.imulab.astrea.sdk.oidc.reserved.ResponseMode
import io.vertx.core.json.Json
import io.vertx.ext.web.RoutingContext
import okhttp3.HttpUrl

object ResponseRenderer {

    fun render(response: AuthorizeEndpointResponse, rc: RoutingContext) {
        val redirectUri = rc.get<String>(Param.redirectUri)!!
        val responseMode = rc.get<String>(OidcParam.responseMode)!!

        when (responseMode) {
            ResponseMode.query -> {
                val url = HttpUrl.parse(redirectUri)!!.newBuilder().apply {
                    response.data.forEach { t, u -> addQueryParameter(t, u) }
                }.build().toString()
                rc.response().setStatusCode(302).apply {
                    response.headers.forEach { t, u -> putHeader(t, u) }
                }.putHeader("Location", url).end()
            }
            ResponseMode.fragment -> {
                val query = HttpUrl.parse(redirectUri)!!.newBuilder().apply {
                    response.data.forEach { t, u -> addQueryParameter(t, u) }
                }.build().query()
                val url = HttpUrl.parse(redirectUri)!!.newBuilder().fragment(query).build().toString()
                rc.response().setStatusCode(302).apply {
                    response.headers.forEach { t, u -> putHeader(t, u) }
                }.putHeader("Location", url).end()
            }
            else -> throw IllegalStateException("illegal state during authorize response rendering.")
        }
    }

    fun render(t: Throwable, rc: RoutingContext) {
        if (t is RedirectionSignal) {
            rc.response().setStatusCode(307).putHeader("Location", t.url).end()
            return
        }

        val e = if (t is OAuthException) t else ServerError.wrapped(t)
        val redirectUri = rc.get<String>(Param.redirectUri) ?: ""
        val responseMode = rc.get<String>(OidcParam.responseMode) ?: ""

        val r = rc.response().apply {
            e.headers.forEach { t, u -> putHeader(t, u) }
        }

        when {
            redirectUri.isEmpty() -> {
                r.statusCode = e.status
                r.end(Json.encode(e.data))
            }
            responseMode == ResponseMode.query -> {
                val url = HttpUrl.parse(redirectUri)!!.newBuilder().apply {
                    e.data.forEach { t, u -> addQueryParameter(t, u) }
                }.build().toString()
                r.statusCode = 302
                r.putHeader("Location", url).end()
            }
            responseMode == ResponseMode.fragment -> {
                val query = HttpUrl.parse(redirectUri)!!.newBuilder().apply {
                    e.data.forEach { t, u -> addQueryParameter(t, u) }
                }.build().query()
                val url = HttpUrl.parse(redirectUri)!!.newBuilder().fragment(query).build().toString()
                r.statusCode = 302
                r.putHeader("Location", url).end()
            }
            else -> throw IllegalStateException("invalid state during error rendering.")
        }
    }
}