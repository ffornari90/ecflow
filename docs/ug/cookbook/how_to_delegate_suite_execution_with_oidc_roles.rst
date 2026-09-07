.. _how_to_delegate_suite_execution_with_oidc_roles:

How to Delegate Suite Execution with OIDC Roles
***********************************************

This recipe describes how to run an ecFlow server as an OpenID Connect (OIDC) native,
multi-tenant service, in which:

- **every** access path is authenticated globally (native ``ecflow_client``,
  ``ecflow_ui``, the built-in HTTPS interface, and the standalone REST API);

- an **administrator** can **delegate** the running of suites to other principals,
  either to individual **users** or to whole **groups of users** identified by a
  **role**.

The design combines two pieces that already exist in ecFlow and extends the second of
them with role awareness:

#. **Authentication** is performed at the edge by `Auth-o-tron
   <https://github.com/ecmwf/auth-o-tron>`_, an ECMWF authentication service, placed in
   front of the server's HTTPS interface. Auth-o-tron validates the caller's credential
   (for example a Keycloak-issued bearer token) and injects a set of trusted identity
   headers (``X-Auth-Username``, ``X-Auth-Roles``) into the request forwarded to the
   ecFlow server. The ecFlow server does **not** validate tokens itself.

#. **Authorisation** is performed inside the ecFlow server using the node-based
   permission model (``ECF_PERMISSIONS``), extended so that a permission can be granted
   to a **role** (``@role``) in addition to an individual user, and so that a configurable
   set of **administrator roles** (``ECF_ADMIN_ROLES``) is allowed to perform any action.

.. contents::
   :local:
   :depth: 2

Overview
========

.. mermaid::

   flowchart LR
       user["ecflow_client / ecflow_ui / REST client"]
       kc["Keycloak (OIDC)"]
       proxy["Reverse proxy (NGINX)"]
       aot["Auth-o-tron"]
       ecf["ecFlow server (--http)"]

       user -- "Bearer &lt;token&gt;" --> proxy
       proxy -- "auth_request" --> aot
       aot -- "validate against JWKS" --> kc
       aot -- "X-Auth-Username, X-Auth-Roles" --> proxy
       proxy -- "authenticated request + trusted headers" --> ecf

The caller obtains an OIDC token from Keycloak and presents it as an HTTP ``Bearer``
credential. The reverse proxy delegates authentication to Auth-o-tron (via the NGINX
``auth_request`` mechanism). Auth-o-tron validates the token against Keycloak's JWKS
endpoint and returns the caller's identity, which the proxy forwards to the ecFlow
server as trusted ``X-Auth-*`` headers. The ecFlow server then evaluates the node-based
permissions, taking both the username and the roles into account.

Authentication with Auth-o-tron and Keycloak
============================================

The ecFlow server is started with the HTTP(S) interface enabled:

.. code-block:: shell

   ecflow_server --http --port 3141

.. note::

   ``--ssl`` is **not** a valid option on the HTTP path: the server only ever
   supports plain HTTP for its own listener (``ServerOptions.cpp`` never sets
   ``Protocol::Https`` from it), and terminates TLS nowhere. Put a
   TLS-terminating reverse proxy in front if HTTPS is required; the server
   still verifies the bearer token itself either way.

The server trusts requests that arrive with a ``Bearer`` (or ``Basic``) authorization
header together with an ``X-Auth-Username`` header: it treats such a request as
*externally authenticated* and does not attempt to verify a password or a token. This is
the existing ``SecureUserX`` identity. The role awareness added by this recipe extends
that identity to also carry the roles supplied in the ``X-Auth-Roles`` header.

Auth-o-tron is configured with a **JWT/JWKS** provider pointing at the Keycloak realm:

.. code-block:: yaml

   # auth-o-tron config (excerpt)
   providers:
     - type: jwt
       # Validate incoming bearer tokens against Keycloak's JWKS endpoint
       jwks_url: "https://keycloak.example/realms/ecmwf/protocol/openid-connect/certs"
       issuer:   "https://keycloak.example/realms/ecmwf"
       # Map Keycloak claims onto the identity headers forwarded to ecFlow
       username_claim: "preferred_username"
       roles_claim:    "realm_access.roles"

With this configuration:

- ``preferred_username`` becomes ``X-Auth-Username``;
- the Keycloak realm roles (``realm_access.roles``) become ``X-Auth-Roles``, as a
  comma-separated list.

.. important::

   **Anti-spoofing.** The ``X-Auth-Username`` and ``X-Auth-Roles`` headers are *trusted*
   by the ecFlow server. The reverse proxy **must strip any client-supplied**
   ``X-Auth-*`` **headers** from the inbound request and set them **only** from the
   Auth-o-tron response. If a client were able to set these headers directly, it could
   impersonate any user or role. Ensure the ecFlow server's HTTPS port is reachable
   *only* through the proxy.

Authorisation with node permissions and roles
=============================================

Authorisation is expressed with the ``ECF_PERMISSIONS`` variable, which can be set at the
server level and overridden on individual nodes. Each entry grants a set of rights to a
principal:

.. code-block:: none

   <principal>:<rights>[,<principal>:<rights>]...

where ``<principal>`` is either:

- an **individual user**, e.g. ``alice``; or
- a **role**, written with a leading ``@``, e.g. ``@ops``.

and ``<rights>`` is any combination of the following characters:

======  =========================================================================
Right   Meaning
======  =========================================================================
``r``   **read**    -- read commands on nodes and their attributes
``w``   **write**   -- write commands on nodes and their attributes
``x``   **execute** -- execute commands on nodes (e.g. run/requeue a task)
``o``   **owner**   -- load new suites
``s``   **sticky**  -- the grant cannot be restricted or removed at a lower level
======  =========================================================================

Example, granting a role and an individual user:

.. code-block:: shell

   # At server level (or on a suite node):
   #  - members of the "ops" role may read, write and execute
   #  - alice may additionally load suites
   edit ECF_PERMISSIONS '@ops:rwx,alice:rwxo'

A caller is allowed to perform an action if **either** their username **or** any of
their roles is granted the required right. Roles are taken from the ``X-Auth-Roles``
header, i.e. from the Keycloak realm roles of the authenticated user.

.. note::

   Backward compatibility is preserved: an entry without a leading ``@`` still grants
   access to an individual user, exactly as before. When no permissions are defined
   anywhere, every action is allowed (the historical, unrestricted behaviour).

Permission hierarchy
--------------------

Permissions are evaluated along the path from the server root to the affected node:

- the **server-level** ``ECF_PERMISSIONS`` provides the initial set of active
  permissions;
- a **suite** node *supersedes* the active permissions (it may introduce new principals);
- a **family** or **task** node *restricts* the active permissions (it may only remove
  rights, never add them);
- a grant marked **sticky** (``s``) is preserved regardless of lower-level restrictions.

This lets an administrator delegate broadly at the top and tighten access deeper in the
tree. Role grants participate in this hierarchy in exactly the same way as user grants.

Administrator roles and delegation
==================================

A set of roles can be designated as **global administrators** through the
``ECF_ADMIN_ROLES`` server option (a comma-separated list of role names):

.. code-block:: shell

   ecflow_server --http \
       ECF_PERMISSIONS='@ops:rwx' \
       ECF_ADMIN_ROLES='ecflow-admins'

Any authenticated identity that carries one of the administrator roles in its
``X-Auth-Roles`` is allowed to perform **any** action, on **any** path, irrespective of
the node permissions. This is the mechanism by which an administrator manages the server
and **delegates** suite execution to others:

- to delegate to an **individual user**, grant that user rights in ``ECF_PERMISSIONS``
  (e.g. ``bob:rwx``);
- to delegate to a **group**, grant the corresponding role (e.g. ``@forecasters:rwx``)
  and manage membership centrally in Keycloak.

Because delegation is expressed with roles that map onto Keycloak realm roles, adding or
removing a user from a group is done entirely in Keycloak -- no change to the suite
definition or a server restart is required.

Client configuration
=====================

No ecFlow client needs code changes; each simply presents an OIDC bearer token over
HTTPS:

- **Native** ``ecflow_client``: connect with ``--http`` (or ``--https`` if a TLS-terminating
  proxy sits in front of the server) and provide the bearer token through the token file
  (``.ecflowapirc``) or ``ECF_AUTHTOKENS``.
- **ecflow_ui**: add the server using the HTTPS connection method and supply the token.
- **Standalone REST** (``ecflow_http``): forwards the authenticated identity (and its
  roles) to the server, so the same delegation rules apply.

Worked example
==============

Delegate a suite to the ``ops`` group while keeping ``analysts`` read-only, and let the
``ecflow-admins`` role manage everything:

.. code-block:: shell

   # Server
   ecflow_server --http \
       ECF_PERMISSIONS='@ops:rwx,@analysts:r' \
       ECF_ADMIN_ROLES='ecflow-admins'

.. code-block:: shell

   # Suite definition: tighten a sensitive family to ops only
   suite operational
     edit ECF_PERMISSIONS '@ops:rwx,@analysts:r'   # supersede at suite level
     family critical
       edit ECF_PERMISSIONS '@ops:rwx'             # restrict: analysts lose access here
       task run
     endfamily
   endsuite

With this configuration:

- a user whose Keycloak roles include ``ops`` can read, write and execute across the
  suite, including ``/operational/critical``;
- a user whose roles include ``analysts`` can read the suite, but has no access to
  ``/operational/critical``;
- a user whose roles include ``ecflow-admins`` can do anything, anywhere.

See also
========

- :ref:`how_to_setup_ecFlow_with_https_authentication` -- Auth-o-tron and NGINX setup.
- :ref:`multi_tenant_reference_environment` -- the reference multi-tenant deployment.
- :ref:`multi_tenant_environment_suite_setup` -- suite adjustments for that deployment.
