# xo-server-ldap-plus

> Advanced LDAP authentication plugin for XO-Server inspired by xo-server-auth-ldap

This plugin allows LDAP users to authenticate to Xen-Orchestra based on LDAP groups.

The first time a user signs in, XO will create a new XO user with the
same identifier. It upadtes the group memberships from LDAP to XO on every login. 

## Install

Installation of the [npm package]

```
> npm install --global xo-server-ldap-plus
```

## Usage

Like all other xo-server plugins, it can be configured directly via
the web iterface, see [the plugin documentation](https://xen-orchestra.com/docs/plugins.html).

## Algorithm

1. If `bind` is defined, attempt to bind using this user.
2. Searches for the user in the directory starting from the `base`
   with the defined `filter`.
3. If found, a bind is attempted using the distinguished name of this
   user and the provided password.
4. Searches for group membership in the configured LDAP groups
5. If found, the user groups are synced from LDAP to XO
6. the user is logged in


## Contributions

Contributions are *very* welcomed, either on the documentation or on
the code.

You may:

- report any [issue](https://github.com/BundesIT/xo-server-ldap-plus/issues)
  you've encountered;
- fork and create a pull request.

## License

AGPL3 © [Piratenpartei BundesIT](https://github.com/BundesIT)
