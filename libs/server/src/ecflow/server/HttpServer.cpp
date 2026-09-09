/*
 * Copyright 2009- ECMWF.
 *
 * This software is licensed under the terms of the Apache Licence version 2.0
 * which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
 * In applying this licence, ECMWF does not waive the privileges and immunities
 * granted to it by virtue of its status as an intergovernmental organisation
 * nor does it submit to any jurisdiction.
 */

#include "ecflow/server/HttpServer.hpp"

#include <algorithm>
#include <cctype>

#include <httplib.h>

#include "ecflow/base/ClientToServerRequest.hpp"
#include "ecflow/base/Identification.hpp"
#include "ecflow/base/ServerToClientResponse.hpp"
#include "ecflow/base/stc/PreAllocatedReply.hpp"
#include "ecflow/core/Base64.hpp"
#include "ecflow/core/Log.hpp"
#include "ecflow/core/ecflow_version.h"
#include "ecflow/server/ServerEnvironment.hpp"
#include "ecflow/service/auth/OidcVerifier.hpp"

inline void log_error(char const* where, boost::beast::error_code ec) {
    using namespace ecf;
    LOG(Log::ERR, where << ": " << ec.message());
}

// NOLINTBEGIN(bugprone-macro-parentheses)
#define LOG_LEVEL(LEVEL, WHERE, MESSAGE)                                      \
    {                                                                         \
        using namespace ecf;                                                  \
        std::cout << LEVEL << " (" << WHERE << "): " << MESSAGE << std::endl; \
    }
// NOLINTEND(bugprone-macro-parentheses)

#define LOG_ERROR(WHERE, MESSAGE) LOG_LEVEL("ERR", WHERE, MESSAGE)
#define LOG_DEBUG(WHERE, MESSAGE) LOG_LEVEL("DBG", WHERE, MESSAGE)

static const std::string CONTENT_TYPE = "application/json";

template <class Body, class Allocator>
void handle_request(const boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>& request,
                    boost::beast::http::response<boost::beast::http::string_body>& response,
                    bool& is_terminate,
                    BaseServer* server,
                    const ecf::service::auth::OidcVerifier* oidc) {
    using response_t = boost::beast::http::response<boost::beast::http::string_body>;

    // Returns a bad request response

    auto const bad_request = [&request](boost::beast::string_view why) {
        response_t res{boost::beast::http::status::bad_request, request.version()};
        res.set(boost::beast::http::field::server, ECFLOW_VERSION);
        res.set(boost::beast::http::field::content_type, CONTENT_TYPE);
        res.keep_alive(request.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Returns a 401 Unauthorized response (used when in-server OIDC verification rejects a token)

    auto const unauthorized = [&request](boost::beast::string_view why) {
        response_t res{boost::beast::http::status::unauthorized, request.version()};
        res.set(boost::beast::http::field::server, ECFLOW_VERSION);
        res.set(boost::beast::http::field::content_type, CONTENT_TYPE);
        res.set(boost::beast::http::field::www_authenticate, "Bearer");
        res.keep_alive(request.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Handle only POST requests.
    // NOTE: the `return` is essential. Without it execution fell through to
    // restore_from_string() below, which constructs a cereal::JSONInputArchive over an
    // empty body and THROWS. That throw escaped handle_request() and on_read() into the
    // asio completion handler, killing the connection with no HTTP response at all -
    // which a reverse proxy reports as "502 upstream prematurely closed connection".
    if (request.method() != boost::beast::http::verb::post) {
        response = bad_request("Unknown HTTP-method");
        return;
    }

    ClientToServerRequest inbound_request;
    ServerToClientResponse outbound_response;

    // 1) Retrieve inbound_request from request body.
    // A body that is not a valid cereal archive (health check, port scan, stray GET
    // turned POST) must produce a 400, never an exception out of the session.
    try {
        ecf::restore_from_string(request.body(), inbound_request);
    }
    catch (const std::exception& e) {
        LOG_DEBUG("HttpServer::handle_request", "Malformed request body: " << e.what());
        response = bad_request("Malformed request body");
        return;
    }

    for (auto& field : request) {
        LOG_DEBUG("HttpServer::handle_request",
                  "Request header field: " << field.name_string() << " = " << field.value());
    }

    {
        ecf::Identity identity = ecf::Identity::make_none();

        // In-server authentication. The identity is derived FROM THE REQUEST ITSELF; no external
        // edge (reverse proxy / auth service) is trusted, so the X-Auth-* request headers are
        // deliberately IGNORED (with nothing in front of the server they would be trivially
        // forgeable).
        //   * Authorization: Bearer <jwt> -> the OIDC token is VERIFIED in-server (RS256 signature
        //     against the Keycloak JWKS, plus issuer/expiry/audience); username + roles come from
        //     the verified claims.
        //   * Authorization: Basic <u:p>  -> classic credentials, checked in-server against passwd.
        //   * otherwise                   -> the identity carried by the inbound command (native TCP).
        bool found_basic_security  = false;
        bool found_bearer_security = false;
        std::string username;
        std::string password;
        std::vector<std::string> roles;
        {
            // Look the header up by Beast's well-known field enum, NOT by string.
            // HTTP header names are case-insensitive (RFC 7230 s3.2) and a reverse
            // proxy is free to normalise them: nginx forwards "authorization" in
            // lower case, so a `name_string() == "Authorization"` comparison silently
            // failed behind the ingress. The request then fell through to the inbound
            // command's identity ({UserX: ...}, no roles) instead of the verified OIDC
            // one ({SecureUserX: ...} with realm roles), and every authenticated user
            // was refused by the node ACL.
            auto found = request.find(boost::beast::http::field::authorization);
            if (found != std::end(request)) {

                auto header = std::string{found->value()};
                LOG_DEBUG("HttpServer::handle_request", "Found Authorization header");

                auto space_separator = header.find(' ');
                if (space_separator == std::string::npos) {
                    auto error = std::string{"Incorrect Authorization header, unable to find space separator"};
                    LOG_ERROR("HttpServer::handle_request", error);
                    response = bad_request(error);
                    return;
                }

                auto tag   = header.substr(0, space_separator);
                auto value = header.substr(space_separator + 1, std::string::npos);
                // The auth-scheme token is case-insensitive (RFC 7235 s2.1).
                std::transform(tag.begin(), tag.end(), tag.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (tag == "basic") {
                    // The Basic tag is processed to extract username and password
                    found_basic_security = true;
                    auto decoded         = ecf::decode_base64(value);
                    auto colon_separator = decoded.find(':');
                    username             = decoded.substr(0, colon_separator);
                    password             = decoded.substr(colon_separator + 1, std::string::npos);
                }
                else if (tag == "bearer") {
                    // Verify the OIDC access token in-server and derive identity + roles from the
                    // VERIFIED claims. Reject (401) if verification fails or OIDC is not configured.
                    if (oidc == nullptr || !oidc->enabled()) {
                        response =
                            unauthorized("Bearer token presented but in-server OIDC verification is not configured");
                        return;
                    }
                    auto verified = oidc->verify(value);
                    if (!verified) {
                        response = unauthorized("Invalid, expired or untrusted OIDC token");
                        return;
                    }
                    username              = verified->username;
                    roles                 = verified->roles;
                    found_bearer_security = true;
                }
                else {
                    // If no Basic or Bearer tag, then ignore the Authorisation header,
                    // and use the identity from the inbound_request
                }
            }
        }

        if (found_bearer_security) {
            LOG_DEBUG("HttpServer::handle_request", "Identity from VERIFIED OIDC Bearer token: " << username);
            identity = ecf::Identity::make_secure_user(username, roles);
        }
        else if (found_basic_security) {
            LOG_DEBUG("HttpServer::handle_request", "Identity from Authorization: Basic (" << username << ")");
            identity = ecf::Identity::make_user(username, password);
        }
        else {
            if (request.find(boost::beast::http::field::authorization) != std::end(request)) {
                LOG_ERROR("HttpServer::handle_request",
                          "An Authorization header is present but was not usable "
                          "(unrecognised scheme?); falling back to the inbound command identity");
            }
            LOG_DEBUG("HttpServer::handle_request", "Identity extracted from inbound Command");
            auto cmd = inbound_request.get_cmd();
            identity = ecf::identify(cmd);
        }

        LOG_DEBUG("HttpServer::handle_request", "Identity extracted is " << identity.as_string());

        inbound_request.get_cmd()->set_identity(std::move(identity));
    }

    // 2) Handle request, as per TcpBaseServer::handle_request()
    {
        // Tag termination request, to be handled by the caller
        is_terminate = inbound_request.terminateRequest();

        try {
            // Service the inbound request, handling the request will populate the outbound_response_
            // Note:: Handle request will first authenticate
            outbound_response.set_cmd(inbound_request.handleRequest(server));
        }
        catch (std::exception& e) {
            outbound_response.set_cmd(PreAllocatedReply::error_cmd(e.what()));
        }

        // Clean up after inbound_request_ has run. i.e like re-claiming memory
        inbound_request.cleanup();
    }

    // 3) Serialize outbound_response into response body
    std::string outbound;
    ecf::save_as_string(outbound, outbound_response);

    outbound_response.cleanup();

    // 4) Ship response
    boost::beast::http::string_body::value_type body = outbound;

    // Cache the size since we need it after the move
    auto const size = body.size();

    // Respond to POST request
    response = response_t{std::piecewise_construct,
                          std::make_tuple(std::move(body)),
                          std::make_tuple(boost::beast::http::status::ok, request.version())};
    response.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(boost::beast::http::field::content_type, CONTENT_TYPE);
    response.content_length(size);
    response.keep_alive(request.keep_alive());
}

// Handles an HTTP server connection
class HttpSession : public std::enable_shared_from_this<HttpSession> {
    boost::asio::ip::tcp::socket socket_;
    // Buffers for incoming and outgoing data
    boost::beast::flat_buffer buffer_{};
    boost::beast::http::request<boost::beast::http::string_body> request_{};
    boost::beast::http::response<boost::beast::http::string_body> response_{};
    bool is_terminate_{false};
    // The Http server that owns this session
    HttpServer* owner_;

    friend class HttpServer;

public:
    // Take ownership of the stream
    HttpSession(boost::asio::ip::tcp::socket&& socket, HttpServer* owner)
        : socket_(std::move(socket)),
          owner_{owner} {}

    void run() {
        // Clear the incoming and outgoing data buffers used buy the session
        buffer_   = {};
        request_  = {};
        response_ = {};

        boost::asio::dispatch(socket_.get_executor(), [self = shared_from_this()]() { self->do_read(); });
    }

    void do_read() {
        boost::beast::http::async_read(
            socket_,
            buffer_,
            request_,
            [self = shared_from_this()](boost::beast::error_code ec, std::size_t bytes_transferred) {
                self->on_read(ec, bytes_transferred);
            });
    }

    void on_read(boost::beast::error_code ec, [[maybe_unused]] std::size_t bytes_transferred) {

        // Handle connection that has been closed
        if (ec == boost::beast::http::error::end_of_stream) {
            return do_close();
        }

        // Handle eventual read error
        if (ec) {
            return log_error("HttpSession::on_read", ec);
        }

        // Handle actual request. A throw here must never escape into the asio
        // completion handler - that closes the connection with no response and the
        // proxy reports 502.
        try {
            handle_request(request_, response_, is_terminate_, owner_->server(), owner_->oidc_verifier());
        }
        catch (const std::exception& e) {
            // NOTE: the only helper in this file is
            //   inline void log_error(char const* where, boost::beast::error_code ec)
            // (HttpServer.cpp:25) - it cannot take a string, so use LOG directly.
            LOG(ecf::Log::ERR, "HttpSession::on_read: " << e.what());
            response_ = {};
            response_.result(boost::beast::http::status::internal_server_error);
            response_.version(request_.version());
            response_.set(boost::beast::http::field::server, ECFLOW_VERSION);
            response_.set(boost::beast::http::field::content_type, CONTENT_TYPE);
            response_.keep_alive(false);
            response_.body() = "Internal server error";
            response_.prepare_payload();
        }

        // Send the response
        send_response();
    }

    void send_response() {
        // Write the response
        boost::beast::http::async_write(
            socket_,
            response_,
            [self = shared_from_this()](boost::beast::error_code ec, std::size_t bytes_transferred) {
                self->on_write(ec, bytes_transferred);
            });
    }

    void on_write(boost::beast::error_code ec, [[maybe_unused]] std::size_t bytes_transferred) {
        // Handle eventual write error
        if (ec) {
            return log_error("HttpSession::on_write", ec);
        }

        // Honour keep-alive. Closing unconditionally broke reverse-proxy upstream
        // keepalive pools: nginx would reuse a socket this server had already
        // half-closed, producing intermittent 502s on valid POST /v1/ecflow requests.
        if (!response_.keep_alive()) {
            return do_close();
        }

        // Reset for the next request on this connection
        response_ = {};
        request_  = {};
        do_read();
    }

    void do_close() {
        // Send a TCP shutdown
        boost::beast::error_code ec;
        socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);

        // At this point the connection is closed gracefully

        // Handle terminate request (in case the request was a termination request, the owning server must terminate)
        owner_->handle_terminate(is_terminate_);
    }
};

HttpServer::HttpServer(BaseServer* server, boost::asio::io_context& io, ServerEnvironment& env)
    : server_{server},
      io_{io},
      acceptor_{io} {
    boost::beast::error_code ec;

    // Configure in-server OIDC Bearer-token verification from the server environment.
    // The verifier is only active when ECF_OIDC_ISSUER + ECF_OIDC_JWKS_URI are set.
    {
        ecf::service::auth::OidcVerifier::Config oidc_config;
        oidc_config.issuer         = env.oidc_issuer();
        oidc_config.jwks_uri       = env.oidc_jwks_uri();
        oidc_config.audience       = env.oidc_audience();
        oidc_config.username_claim = env.oidc_username_claim();
        oidc_config.roles_claim    = env.oidc_roles_claim();
        oidc_verifier_             = std::make_unique<ecf::service::auth::OidcVerifier>(std::move(oidc_config));
        if (oidc_verifier_->enabled()) {
            LOG(ecf::Log::MSG, "HttpServer: in-server OIDC verification enabled (issuer=" << env.oidc_issuer() << ")");
        }
    }

    boost::asio::ip::tcp::endpoint endpoint(env.tcp_protocol(), env.port());

    // Open the acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) {
        log_error("HttpServer::open", ec);
        return;
    }

    // Allow address reuse
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
        log_error("HttpServer::set_option", ec);
        return;
    }

    // Bind to the server address
    acceptor_.bind(endpoint, ec);
    if (ec) {
        log_error("HttpServer::bind", ec);
        return;
    }

    // Start listening for connections
    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        log_error("HttpServer::listen", ec);
        return;
    }

    do_accept();
}

void HttpServer::handle_terminate(bool terminate) {
    if (terminate) {
        if (server_->debug()) {
            std::cout << "   <-- HttpServer exiting server via terminate()" << std::endl;
        }

        boost::asio::post(io_, [this]() {
            server_->handle_terminate();
            acceptor_.close();
            io_.stop();
        });
    }
}

void HttpServer::do_accept() {
    acceptor_.async_accept(io_, [this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket) {
        on_accept(ec, std::move(socket), this->server_);
    });
}

void HttpServer::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket, BaseServer* server) {
    if (ec) {
        log_error("HttpServer::on_accept", ec);
        // Terminate the server
        return;
    }
    else {
        // Create a new session (and thus, implicitly, a new strand) to process the connection
        std::make_shared<HttpSession>(std::move(socket), this)->run();
    }

    // Accept another connection
    do_accept();
}
