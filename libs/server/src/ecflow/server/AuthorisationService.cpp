/*
 * Copyright 2009- ECMWF.
 *
 * This software is licensed under the terms of the Apache Licence version 2.0
 * which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
 * In applying this licence, ECMWF does not waive the privileges and immunities
 * granted to it by virtue of its status as an intergovernmental organisation
 * nor does it submit to any jurisdiction.
 */

#include "ecflow/server/AuthorisationService.hpp"

#include <algorithm>

#include "ecflow/base/AbstractServer.hpp"
#include "ecflow/core/Overload.hpp"
#include "ecflow/core/WhiteListFile.hpp"
#include "ecflow/node/NodePathAlgorithms.hpp"
#include "ecflow/node/permissions/ActivePermissions.hpp"

namespace ecf {

struct AuthorisationService::Impl
{
    explicit Impl(UnrestrictedRules&& rules)
        : rules_(std::move(rules)) {}
    explicit Impl(NodeRules&& rules)
        : rules_(std::move(rules)) {}
    explicit Impl(WhiteListRules&& rules)
        : rules_(std::move(rules)) {}

    std::variant<UnrestrictedRules, WhiteListRules, NodeRules> rules_;
};

AuthorisationService::AuthorisationService() = default;

AuthorisationService::AuthorisationService(std::unique_ptr<Impl>&& impl)
    : impl_{std::move(impl)} {
}

AuthorisationService::AuthorisationService(AuthorisationService&& rhs) noexcept
    : impl_{std::move(rhs.impl_)},
      admin_roles_{std::move(rhs.admin_roles_)} {
}

AuthorisationService::~AuthorisationService() = default;

AuthorisationService& AuthorisationService::operator=(AuthorisationService&& rhs) noexcept {
    if (this != &rhs) {
        impl_        = std::move(rhs.impl_);
        admin_roles_ = std::move(rhs.admin_roles_);
    }
    return *this;
}

bool AuthorisationService::good() const {
    return impl_ != nullptr;
}

bool AuthorisationService::content_varies_by_identity() const {
    if (!good()) {
        // Without rules, every identity observes the same content
        return false;
    }

    bool varies = false;
    std::visit(overload{[&varies](const UnrestrictedRules&) { varies = false; },
                        // The white list file governs the operations each identity is allowed to perform,
                        // but does not restrict the content visible in the Defs tree
                        [&varies](const WhiteListRules&) { varies = false; },
                        // Node level permissions are, by design, specific to each identity
                        [&varies](const NodeRules&) { varies = true; }},
               impl_->rules_);

    return varies;
}

bool AuthorisationService::has_admin_role(const Identity& identity) const {
    if (admin_roles_.empty()) {
        return false;
    }
    const auto& roles = identity.roles();
    return std::any_of(std::begin(roles), std::end(roles), [this](const std::string& role) {
        return std::find(std::begin(admin_roles_), std::end(admin_roles_), role) != std::end(admin_roles_);
    });
}

bool AuthorisationService::allows(const Identity& identity, const Defs& defs, Allowed required) const {
    return allows(identity, defs, paths_t{ROOT}, required);
}

bool AuthorisationService::allows(const Identity& identity,
                                  const Defs& defs,
                                  const path_t& path,
                                  Allowed required) const {
    return allows(identity, defs, paths_t{path}, required);
}

bool AuthorisationService::allows(const Identity& identity,
                                  const Defs& defs,
                                  const paths_t& paths,
                                  Allowed required) const {
    if (!good()) {
        // When no rules are loaded, we allow everything...
        // Dangerous, but backward compatible!
        return true;
    }

    // OURS: global administrators (identity carries an admin role) may perform any action, on any
    // path. This is how an administrator manages the server and delegates suite execution to others.
    if (has_admin_role(identity)) {
        return true;
    }

    bool allowed = false;
    std::visit(overload{[&allowed](const UnrestrictedRules&) { allowed = true; },
                        [&allowed, &identity, &paths, &required](const WhiteListRules& rules) {
                            // Apply white list rules

                            constexpr Allowed read_mask  = Allowed::READ;
                            constexpr Allowed write_mask = Allowed::WRITE | Allowed::EXECUTE | Allowed::OWNER;

                            if ((required & read_mask) != Allowed::NONE) {
                                allowed = rules.file_.verify_read_access(identity.username().value(), paths);
                            }
                            else if ((required & write_mask) != Allowed::NONE) {
                                allowed = rules.file_.verify_write_access(identity.username().value(), paths);
                            }
                            else {
                                allowed = false;
                            }
                        },
                        [&allowed, &defs, &identity, &paths, &required, this](const NodeRules& rules) {
                            for (auto&& path : paths) {
                                ActivePermissions active = permissions_at(identity, defs, path);
                                std::cout << "*** [DBG] AuthorisationService::allows: User ["
                                          << identity.username().value() << "] checking permissions for path [" << path
                                          << "] with required permissions [" << allowed_to_string(required) << "]"
                                          << std::endl;
                                std::cout << "*** [DBG] AuthorisationService::allows: User ["
                                          << identity.username().value() << "] roles=[";
                                for (const auto& r : identity.roles()) { std::cout << r << " "; }
                                std::cout << "] admin_roles=[";
                                for (const auto& r : admin_roles_) { std::cout << r << " "; }
                                std::cout << "]" << std::endl;
                                std::cout << "*** [DBG] AuthorisationService::allows: User ["
                                          << identity.username().value() << "] " << active << std::endl;
                                // OURS: role-aware check -- match the caller's username AND any of
                                // the roles carried on the verified OIDC identity.
                                allowed = active.allows(identity.username(), identity.roles(), required);
                                std::cout << "*** [DBG] AuthorisationService::allows: User ["
                                          << identity.username().value()
                                          << "] is allowed: " << (allowed ? "true" : "false") << std::endl;
                                if (!allowed) {
                                    break;
                                }
                            }
                        }},
               impl_->rules_);

    std::cout << "*** [DBG] AuthorisationService::allows: User [" << identity.username().value()
              << "] is allowed: " << (allowed ? "true" : "false") << " >> (FINAL)" << std::endl;

    return allowed;
}

AuthorisationService::result_t AuthorisationService::load_permissions_unrestricted() {
    return result_t::success(AuthorisationService(std::make_unique<Impl>(UnrestrictedRules{})));
}

AuthorisationService::result_t AuthorisationService::load_permissions_from_nodes() {
    return result_t::success(AuthorisationService(std::make_unique<Impl>(NodeRules{})));
}

AuthorisationService::result_t AuthorisationService::load_permissions_from_whitelist(const WhiteListFile& whitelist) {
    return result_t::success(AuthorisationService(std::make_unique<Impl>(WhiteListRules{whitelist})));
}

void AuthorisationService::init(const Permissions& permissions) {
    if (permissions.is_empty()) {
        impl_ = std::make_unique<AuthorisationService::Impl>(WhiteListRules{WhiteListFile{}});
    }
    else {
        impl_ = std::make_unique<AuthorisationService::Impl>(NodeRules{});
    }
}

void AuthorisationService::set_admin_roles(std::vector<std::string> roles) {
    admin_roles_ = std::move(roles);
}

} // namespace ecf
