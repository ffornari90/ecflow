/*
 * Copyright 2009- ECMWF.
 *
 * This software is licensed under the terms of the Apache Licence version 2.0
 * which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
 * In applying this licence, ECMWF does not waive the privileges and immunities
 * granted to it by virtue of its status as an intergovernmental organisation
 * nor does it submit to any jurisdiction.
 */

#ifndef ecflow_node_permissions_Permission_HPP
#define ecflow_node_permissions_Permission_HPP

#include <algorithm>
#include <utility>

#include "ecflow/core/Identity.hpp"
#include "ecflow/node/permissions/Allowed.hpp"

namespace ecf {

///
/// \brief Distinguishes whether a Permission grants access to a named user or to a named role.
///
/// A `User` permission matches a single username, whereas a `Role` permission matches any
/// identity that possesses the given role (as asserted by the external Authentication mechanism).
///
enum class PrincipalKind : std::uint8_t {
    User,
    Role
};

/**
 * \brief Represents a permission granted to a specific principal (a user or a role) by linking a principal name
 * with a set of allowed permissions.
 */
class Permission {
public:
    /// Construct a permission granted to a named user.
    Permission(Username user, Allowed allowed)
        : kind_{PrincipalKind::User},
          name_{std::move(user)},
          allowed_{allowed} {}

    /// Construct a permission granted to a named role.
    [[nodiscard]] static Permission for_role(const std::string& role, Allowed allowed) {
        return Permission{PrincipalKind::Role, Username{role}, allowed};
    }

    /**
     * \brief Check whether this permission grants the requested access to the given identity.
     *
     * For a user permission, the identity's username must match the granted principal.
     * For a role permission, the identity must possess the granted role.
     *
     * @param user the identity's username
     * @param roles the identity's roles
     * @param requested the required permission bits
     * @return true if this permission both applies to the identity and includes the requested access
     */
    [[nodiscard]] bool allows(const Username& user, const Roles& roles, Allowed requested) const {
        if (!contains(allowed_, requested)) {
            return false;
        }
        if (kind_ == PrincipalKind::User) {
            return user == name_;
        }
        // PrincipalKind::Role: the identity is granted access if it possesses the named role
        return std::find(std::begin(roles), std::end(roles), name_.value()) != std::end(roles);
    }

    /// Convenience overload for an identity that carries no roles.
    [[nodiscard]] bool allows(const Username& user, Allowed requested) const {
        return allows(user, no_roles(), requested);
    }

    /// Two permissions share the same principal when both kind and name are equal.
    /// Used when combining permissions across the node hierarchy.
    [[nodiscard]] bool same_principal(const Permission& other) const {
        return kind_ == other.kind_ && name_ == other.name_;
    }

    /// Return a copy of this permission for the same principal but with a different set of allowed bits.
    [[nodiscard]] Permission with_allowed(Allowed allowed) const { return Permission{kind_, name_, allowed}; }

    [[nodiscard]] PrincipalKind kind() const { return kind_; }
    [[nodiscard]] bool is_role() const { return kind_ == PrincipalKind::Role; }

    Username username() const { return name_; }
    Allowed allowed() const { return allowed_; }

private:
    Permission(PrincipalKind kind, Username name, Allowed allowed)
        : kind_{kind},
          name_{std::move(name)},
          allowed_{allowed} {}

    PrincipalKind kind_;
    Username name_;
    Allowed allowed_;
};

} // namespace ecf

#endif /* ecflow_node_permissions_Permission_HPP */
