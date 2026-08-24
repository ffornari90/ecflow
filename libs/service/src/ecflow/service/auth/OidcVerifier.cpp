/*
 * Copyright 2009- ECMWF.
 *
 * This software is licensed under the terms of the Apache Licence version 2.0
 * which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
 * In applying this licence, ECMWF does not waive the privileges and immunities
 * granted to it by virtue of its status as an intergovernmental organisation
 * nor does it submit to any jurisdiction.
 */

#include "ecflow/service/auth/OidcVerifier.hpp"

#include "ecflow/core/Log.hpp"

// The JWKS fetch uses Boost.Beast (which the ecFlow built-in server itself is
// built on). We deliberately do NOT use cpp-httplib here: ecFlow includes
// cpp-httplib both with and without CPPHTTPLIB_OPENSSL_SUPPORT across different
// translation units, so introducing an OpenSSL-enabled httplib::Client in this
// TU triggers an ODR mismatch (and a crash). Beast is included consistently.
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

// jwt-cpp (header-only) using the nlohmann-json traits already vendored in ecFlow.
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>

namespace ecf::service::auth {

namespace {

using jwt_traits = jwt::traits::nlohmann_json;
namespace beast = boost::beast;
namespace http  = beast::http;
namespace asio  = boost::asio;
using tcp       = asio::ip::tcp;

// Traverse a dotted path (e.g. "realm_access.roles") into a JWT payload and
// collect the string entries of the array found there.
std::vector<std::string> extract_roles(const nlohmann::json& payload, const std::string& dotted) {
    std::vector<std::string> out;
    const nlohmann::json* node   = &payload;
    std::string::size_type start = 0;
    while (true) {
        auto dot         = dotted.find('.', start);
        std::string part = dotted.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
        if (!node->is_object() || !node->contains(part)) {
            return out;
        }
        node = &((*node)[part]);
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    if (node->is_array()) {
        for (const auto& value : *node) {
            if (value.is_string()) {
                out.push_back(value.get<std::string>());
            }
        }
    }
    return out;
}

struct Url
{
    bool https = false;
    std::string host;
    std::string port;
    std::string target = "/";
};

Url parse_url(const std::string& uri) {
    Url u;
    auto sep = uri.find("://");
    if (sep == std::string::npos) {
        return u; // caller checks host.empty()
    }
    std::string scheme = uri.substr(0, sep);
    std::string rest   = uri.substr(sep + 3);
    u.https            = (scheme == "https");
    auto slash         = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    u.target             = (slash == std::string::npos) ? std::string{"/"} : rest.substr(slash);
    auto colon           = hostport.find(':');
    if (colon == std::string::npos) {
        u.host = hostport;
        u.port = u.https ? "443" : "80";
    }
    else {
        u.host = hostport.substr(0, colon);
        u.port = hostport.substr(colon + 1);
    }
    return u;
}

// Perform a synchronous HTTP(S) GET and return the response body.
template <typename Stream>
std::string do_get(Stream& stream, const std::string& host, const std::string& target) {
    http::request<http::empty_body> req{http::verb::get, target, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, "ecflow-oidc-verifier");
    req.set(http::field::accept, "application/json");
    http::write(stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);
    return res.body();
}

} // namespace

OidcVerifier::OidcVerifier(Config config)
    : config_(std::move(config)) {}

std::string OidcVerifier::fetch_jwks() const {
    Url url = parse_url(config_.jwks_uri);
    if (url.host.empty()) {
        LOG(Log::ERR, "OidcVerifier: malformed ECF_OIDC_JWKS_URI '" << config_.jwks_uri << "'");
        return {};
    }

    try {
        asio::io_context ioc;
        tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(url.host, url.port);

        std::string body;
        if (url.https) {
            asio::ssl::context ctx(asio::ssl::context::tls_client);
            // Playground: do not fail on certificate verification. The JWT
            // signature itself is still cryptographically verified afterwards.
            ctx.set_verify_mode(asio::ssl::verify_none);
            asio::ssl::stream<tcp::socket> stream(ioc, ctx);
            // SNI - many servers (and Keycloak behind a vhost) require it.
            SSL_set_tlsext_host_name(stream.native_handle(), url.host.c_str());
            asio::connect(stream.next_layer(), endpoints);
            stream.handshake(asio::ssl::stream_base::client);
            body = do_get(stream, url.host, url.target);
            beast::error_code ec;
            stream.shutdown(ec); // ignore shutdown errors
        }
        else {
            tcp::socket socket(ioc);
            asio::connect(socket, endpoints);
            body = do_get(socket, url.host, url.target);
            beast::error_code ec;
            socket.shutdown(tcp::socket::shutdown_both, ec);
        }
        return body;
    }
    catch (const std::exception& e) {
        LOG(Log::ERR, "OidcVerifier: JWKS fetch from '" << config_.jwks_uri << "' failed: " << e.what());
        return {};
    }
}

std::string OidcVerifier::pem_for_kid(const std::string& kid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (jwks_json_.empty()) {
            jwks_json_ = fetch_jwks();
            if (jwks_json_.empty()) {
                return {};
            }
        }
        try {
            auto jwks = jwt::parse_jwks<jwt_traits>(jwks_json_);
            auto jwk  = jwks.get_jwk(kid);
            auto x5c  = jwk.get_x5c_key_value();
            if (!x5c.empty()) {
                return jwt::helper::convert_base64_der_to_pem(x5c);
            }
            return {}; // key found but carries no x5c certificate (Keycloak always provides one)
        }
        catch (const std::exception&) {
            // Unknown kid (e.g. key rotation) or a stale cache: drop and refetch once.
            jwks_json_.clear();
        }
    }
    return {};
}

std::optional<OidcVerifier::VerifiedIdentity> OidcVerifier::verify(const std::string& token) const {
    if (!config_.enabled()) {
        return std::nullopt;
    }

    try {
        auto decoded = jwt::decode<jwt_traits>(token);

        const std::string kid = decoded.get_key_id();
        std::string pem       = pem_for_kid(kid);
        if (pem.empty()) {
            LOG(Log::ERR, "OidcVerifier: no signing key available for kid '" << kid << "'");
            return std::nullopt;
        }

        auto verifier = jwt::verify<jwt_traits>()
                            .allow_algorithm(jwt::algorithm::rs256(pem, "", "", ""))
                            .with_issuer(config_.issuer)
                            .leeway(60); // tolerate up to 60s of clock skew
        if (!config_.audience.empty()) {
            verifier.with_audience(config_.audience);
        }
        verifier.verify(decoded); // throws on any verification failure

        // The token is now cryptographically verified; extract the claims.
        nlohmann::json payload = nlohmann::json::parse(decoded.get_payload());

        VerifiedIdentity identity;
        if (payload.contains(config_.username_claim) && payload[config_.username_claim].is_string()) {
            identity.username = payload[config_.username_claim].get<std::string>();
        }
        if (identity.username.empty()) {
            LOG(Log::ERR, "OidcVerifier: username claim '" << config_.username_claim << "' missing/empty");
            return std::nullopt;
        }
        identity.roles = extract_roles(payload, config_.roles_claim);

        return identity;
    }
    catch (const std::exception& e) {
        LOG(Log::ERR, "OidcVerifier: token verification failed: " << e.what());
        return std::nullopt;
    }
}

} // namespace ecf::service::auth
