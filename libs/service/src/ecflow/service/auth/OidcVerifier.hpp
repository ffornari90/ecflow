/*
 * Copyright 2009- ECMWF.
 *
 * This software is licensed under the terms of the Apache Licence version 2.0
 * which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
 * In applying this licence, ECMWF does not waive the privileges and immunities
 * granted to it by virtue of its status as an intergovernmental organisation
 * nor does it submit to any jurisdiction.
 */

#ifndef ecflow_service_auth_OidcVerifier_HPP
#define ecflow_service_auth_OidcVerifier_HPP

#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ecf::service::auth {

///
/// OidcVerifier performs *in-server* verification of Keycloak (OpenID Connect)
/// access tokens (RS256 JWTs). It fetches and caches the realm JWKS, validates
/// the token signature + issuer + expiry (+ audience when configured), and
/// extracts the caller's username and roles from the verified claims.
///
/// This replaces trusting X-Auth-* headers injected by an external reverse
/// proxy / edge auth service: with the verifier in place, ecflow_server no
/// longer needs anything in front of it to authenticate HTTP(S) clients.
///
class OidcVerifier {
public:
    struct Config
    {
        std::string issuer;                              // e.g. http://keycloak:8080/realms/ecmwf
        std::string jwks_uri;                            // e.g. <issuer>/protocol/openid-connect/certs
        std::string audience;                            // optional; empty => audience not checked
        std::string username_claim = "preferred_username";
        std::string roles_claim    = "realm_access.roles"; // dotted path into the JWT payload

        /// OIDC verification is active only when both issuer and jwks_uri are set.
        [[nodiscard]] bool enabled() const { return !issuer.empty() && !jwks_uri.empty(); }
    };

    struct VerifiedIdentity
    {
        std::string username;
        std::vector<std::string> roles;
    };

    explicit OidcVerifier(Config config);

    [[nodiscard]] bool enabled() const { return config_.enabled(); }

    /// Verify a raw JWT (the value after "Bearer "). Returns the verified
    /// identity on success, or std::nullopt on ANY failure (bad signature,
    /// wrong issuer/audience, expired, unknown key, malformed, network error).
    /// Never throws.
    [[nodiscard]] std::optional<VerifiedIdentity> verify(const std::string& token) const;

private:
    /// Return the PEM public key for the given key id, (re)fetching the JWKS if
    /// the key is not in the cache. Empty string if unavailable. Thread-safe.
    [[nodiscard]] std::string pem_for_kid(const std::string& kid) const;

    /// Fetch the JWKS document from config_.jwks_uri (http or https). Empty on error.
    [[nodiscard]] std::string fetch_jwks() const;

    Config config_;
    mutable std::mutex mutex_;
    mutable std::string jwks_json_; // cached raw JWKS document
};

} // namespace ecf::service::auth

#endif /* ecflow_service_auth_OidcVerifier_HPP */
