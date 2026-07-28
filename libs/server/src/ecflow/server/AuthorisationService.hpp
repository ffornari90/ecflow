/*
 * Copyright 2009- ECMWF.
 *
 * This software is licensed under the terms of the Apache Licence version 2.0
 * which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
 * In applying this licence, ECMWF does not waive the privileges and immunities
 * granted to it by virtue of its status as an intergovernmental organisation
 * nor does it submit to any jurisdiction.
 */

#ifndef ecflow_server_AuthorisationService_HPP
#define ecflow_server_AuthorisationService_HPP

#include <string>
#include <vector>

#include "ecflow/core/Filesystem.hpp"
#include "ecflow/core/Identity.hpp"
#include "ecflow/core/Result.hpp"
#include "ecflow/core/WhiteListFile.hpp"
#include "ecflow/node/permissions/ActivePermissions.hpp"

class AbstractServer;
class Defs;

namespace ecf {

class AuthorisationService {
public:
    static constexpr auto ROOT = "/";

    using result_t = Result<AuthorisationService>;
    using path_t   = std::string;
    using paths_t  = std::vector<std::string>;

    AuthorisationService();

    AuthorisationService(const AuthorisationService& rhs)                     = delete;
    AuthorisationService& operator=(const AuthorisationService& rhs) noexcept = delete;
    AuthorisationService(AuthorisationService&& rhs) noexcept;
    AuthorisationService& operator=(AuthorisationService&& rhs) noexcept;

    ~AuthorisationService();

    [[nodiscard]]
    bool good() const;

    /// @brief Indicates whether the content visible to a client depends on the identity of that client.
    ///
    /// The Defs serialisation filters out nodes the requesting identity is not allowed to read, meaning
    /// that the resulting content is only shareable between identities when the active rules are unable
    /// to discriminate between them.
    ///
    /// @return true if the visible content may differ between identities, false if all identities observe
    /// the same content
    [[nodiscard]]
    bool content_varies_by_identity() const;

    /**
     * Verify if the identity is allowed to perform the action on the give paths.
     *
     * @param identity the identity performing the action
     * @param paths the set of path(s) affected by the action
     * @param permission the required permission to perform the action
     * @return true if the identity is allowed to perform the action, false otherwise
     */
    [[nodiscard]]
    bool allows(const Identity& identity, const Defs& defs, Allowed required) const;

    [[nodiscard]]
    bool allows(const Identity& identity, const Defs& defs, const path_t& path, Allowed required) const;

    [[nodiscard]]
    bool allows(const Identity& identity, const Defs& defs, const paths_t& paths, Allowed required) const;

    [[nodiscard]]
    static result_t load_permissions_unrestricted();

    [[nodiscard]]
    static result_t load_permissions_from_nodes();

    [[nodiscard]]
    static result_t load_permissions_from_whitelist(const WhiteListFile& whitelist);

    static AuthorisationService make_unrestricted();

    static AuthorisationService make_from_nodes();

    static AuthorisationService make_from_whitelist(const WhiteListFile& whitelist);

    void init(const Permissions& permissions);

    /**
     * Configure the set of roles that grant global administrator privileges.
     *
     * An identity that possesses any of these roles is allowed to perform any action, on any path,
     * regardless of the active node/white-list permissions. This is the mechanism by which an
     * administrator can manage and delegate the whole server (see ECF_ADMIN_ROLES).
     *
     * @param roles the administrator roles (typically parsed from ECF_ADMIN_ROLES)
     */
    void set_admin_roles(std::vector<std::string> roles);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::vector<std::string> admin_roles_;

    [[nodiscard]] bool has_admin_role(const Identity& identity) const;

    AuthorisationService(std::unique_ptr<Impl>&& impl);
};

} // namespace ecf

#endif /* ecflow_server_AuthorisationService_HPP */
