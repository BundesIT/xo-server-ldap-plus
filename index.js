// advanced ldap connection plugin
// allows to declare groups with access
// and syncs ldap groups to xo groups

var Promise = require("bluebird");
var fsp = require('fs-promise');
var ldap = require('ldapjs');
var eventToPromise = require('event-to-promise')
var escape = require('ldapjs/lib/filters/escape')
var bunyan = require('bunyan');

exports.configurationSchema = {
    type: 'object',
    properties: {
        uri: {
            description: 'URI of the LDAP server.',
            type: 'string'
        },
        certificateAuthorities: {
            description: `
Paths to CA certificates to use when connecting to SSL-secured LDAP servers.
If not specified, it will use a default set of well-known CAs.
`.trim(),
            type: 'array',
            items: {
                type: 'string'
            }
        },
        checkCertificate: {
            description: 'Enforce the validity of the server\'s certificates. You can disable it when connecting to servers that use a self-signed certificate.',
            type: 'boolean',
            default: true
        },
        bind: {
            description: 'Credentials to use before looking for the user record.',
            type: 'object',
            properties: {
                dn: {
                    description: `
Distinguished name of the user permitted to search the LDAP directory for the user to authenticate.
For Microsoft Active Directory, it can also be \`<user>@<domain>\`.
`.trim(),
                    type: 'string'
                },
                password: {
                    description: 'Password of the user permitted of search the LDAP directory.',
                    type: 'string'
                }
            },
            required: ['dn', 'password']
        },
        userBase: {
            description: 'The base is the part of the description tree where the users are looked for.',
            type: 'string'
        },
        userFilter: {
            description: `
Filter used to find the user.
For Microsoft Active Directory, you can try one of the following filters:
- \`(cn={{name}})\`
- \`(sAMAccountName={{name}})\`
- \`(sAMAccountName={{name}}@<domain>)\`
- \`(userPrincipalName={{name}})\`
`.trim(),
            type: 'string',
            default: '(uid={{name}})'
        },
        groupBase: {
            description: 'The base is the part of the description tree where the groups are looked for.',
            type: 'string'
        },
        groups: {
            type: 'array',
            description: 'groups that have access and should be synced',
            items: {
                type: 'string'
            }
        }
    },
    required: ['uri', 'userBase', 'groupBase', 'groups']
}

exports.testSchema = {
    type: 'object',
    properties: {
        username: {
            description: 'LDAP username',
            type: 'string'
        },
        password: {
            description: 'LDAP password',
            type: 'string'
        }
    },
    required: ['username', 'password']
}

var bind = function bind(fn, thisArg) {
    return function () {
        return fn.apply(thisArg, arguments);
    };
};

var VAR_RE = /\{\{([^}]+)\}\}/g;
var evalFilter = function evalFilter(filter, vars) {
    return filter.replace(VAR_RE, function (_, name) {
        var value = vars[name];

        if (value === undefined) {
            throw new Error('invalid variable: ' + name);
        }

        return (0, escape.escape)(value);
    });
};


function ldapPlus(xo) {
    this._xo = xo;
    this._ldapOpts = {
        maxConnections: 5,
        tlsOptions: {},
        log: bunyan.createLogger({
            name: "ldap-debug",
            stream: process.stderr,
            level: "trace"
        })
    }
    this._auth = bind(this.authHandler, this)

    this._xoGroups = {}
}

ldapPlus.prototype.configure = function (configuration) {
    this._bindCreds = configuration.bindCredentials;
    this._userBase = configuration.userBase;
    this._userFilter = configuration.userFilter;
    this._groupBase = configuration.groupBase;
    this._groups = configuration.groups;

    this._ldapOpts.url = configuration.uri

    var _this = this;

    if (configuration.bind) {
        this._ldapOpts.bindDN = configuration.bind.dn
        this._ldapOpts.bindCredentials = configuration.bind.password
    }
    this._ldapOpts.tlsOptions.rejectUnauthorized = configuration.checkCertificate
    if (configuration.certificateAuthorities) {
        _this = this;
        Promise.all(
            configuration.certificateAuthorities.map(path => fsp.readFile(path))
        )
            .done(function (results) {
                _this._ldapOpts.tlsOptions.ca = results
            })
    }

    return this._xo.getAllGroups()
        .then(function (result) {
            for (var i = 0, len = result.length; i < len; ++i) {
                var xoGroupName = result[i].name
                var xoGroupID = result[i].id
                if (configuration.groups.find(function (g) {
                    return g === xoGroupName
                })) {
                    _this._xoGroups[xoGroupName] = xoGroupID
                }
            }
        })
        .then(function () {
            console.log("configuration done")
        })
    // we cache the LDAP <> XO Group Mapping
}

ldapPlus.prototype.authHandler = function (data) {
    var user = data.username;
    var pass = data.password;
    // no user, no password -> out
    if (user === undefined || pass === undefined) {
        return null;
    }

    // create our ldap client
    var client = ldap.createClient(this._ldapOpts)
    // promisify our client
    Promise.promisifyAll(client)

    try {
        var _this = this
        var userUid = undefined

        function bindLDAP() {
            if (_this._bindCreds) {
                return client.bindAsync(_this._bindCreds.dn, _this._bindCreds.password);
            } else {
                return Promise.resolve(client)
            }
        }

        return bindLDAP()
            .then(function () {
                // search the user
                return client.searchAsync(_this._userBase, {
                    scope: 'sub',
                    filter: evalFilter(_this._userFilter, { name: user })
                })
            })
            .then(function (res) {
                var entries = [];
                res.on('searchEntry', function (entry) {
                    entries.push(entry.json)
                })
                return eventToPromise(res, 'end')
                    .then(function () {
                        return Promise.resolve(entries)
                    })
            })
            .then(function (entries) {
                // check all entries if we have a valid login
                // TODO: this is insecure if there are multiple uid's in the subtrees of the searchbase
                var binds = entries.map(function (entry) {
                    return client.bindAsync(entry.objectName, pass)
                        .then(function () {
                            return Promise.resolve(entry)
                        })
                        .catch(function (err) {
                            return Promise.reject(err);
                        })
                })
                return Promise.any(binds)
                    .catch(function (err) { return new Error("missing user") })
            })
            .then(function (ldapUser) {
                // we found the valid user, now let's check if the user is within the allowed / synced _groups

                // get the uid of the user
                var userUid = ldapUser.attributes.find(function (attr) {
                    return attr.type === "uid"
                })
                if (userUid === undefined) {
                    console.log("user does not have a uid", user)
                    return Promise.reject(new Error("missing uid"))
                }
                userUid = userUid.vals[0]

                // group name filters
                var GroupNameFilter = new ldap.OrFilter({
                    filters: _this._groups.map(function (group) {
                        return new ldap.EqualityFilter({
                            attribute: 'cn',
                            value: group
                        })
                    })
                })

                // group filter
                var GroupFilter = new ldap.AndFilter({
                    filters: [
                        new ldap.EqualityFilter({
                            attribute: 'objectclass',
                            value: 'posixGroup'
                        }),
                        GroupNameFilter
                    ]
                })
                var groupResults = []
                return client.searchAsync(_this._groupBase, {
                    filter: GroupFilter,
                    scope: "sub"
                })
                    .then(function (res) {
                        res.on('searchEntry', function (group) {
                            var g = group.json

                            // find the memberUid attribute
                            var memberUids = g.attributes.find(function (attr) {
                                return attr.type === "memberUid"
                            })
                            // check if the group has members
                            if (memberUids) {
                                // check if the user is member of the group
                                var isMember = memberUids.vals.find(function (uid) {
                                    return uid === userUid
                                })
                                if (isMember) {
                                    var ldapGroupName = g.attributes.find(function (attr) {
                                        return attr.type === "cn"
                                    })
                                    groupResults.push(ldapGroupName.vals[0])
                                }
                            }
                        })
                        return eventToPromise(res, 'end')
                            .then(function () {
                                return Promise.resolve(groupResults)
                            })
                    })
            })
            .then(function (groupResults) {
                // if the user is not in an allowed group, exit here
                if (groupResults.length === 0) {
                    return Promise.reject(new Error('user is not in a allowed group'))
                }

                // create the user or get the user obejct from xo
                return _this._xo.registerUser('ldap-plus', user)
                    .then(function (xoUser) {
                        var checkUserGroupMembership = function (userID, groupID, isMember) {
                            return _this._xo.getGroup(groupID)
                                .then(function (xoGroup) {
                                    if (isMember && !xoGroup.users.find(function(u) { return u === userID })) {
                                        return _this._xo.addUserToGroup(xoUser.id, xoGroup.id)
                                    } else if (!isMember && xoGroup.users.find(function(u) { return u === userID })) {
                                        return _this._xo.removeUserFromGroup(xoUser.id, xoGroup.id)
                                    } else {
                                        return Promise.resolve
                                    }
                                })
                        }

                        return Promise.all(
                            Object.keys(_this._xoGroups).map(function (g) {
                                var isMember = false
                                if (groupResults.find(function(r) { return r === g })) {
                                    isMember = true
                                }
                                return checkUserGroupMembership(xoUser.id, _this._xoGroups[g], isMember)
                            })
                        )
                            .then(function (results) {
                                // TODO: check for errors from above

                                // now check if we have any new group, not created yet+
                                return Promise.map(groupResults, function (g) {
                                    if (_this._xoGroups[g] === undefined) {
                                        return _this._xo.createGroup({ name: g })
                                            .then(function (xoGroup) {
                                                _this._xoGroups[g] = xoGroup.id
                                                return _this._xo.addUserToGroup(xoUser.id, xoGroup.id)
                                            })
                                    } else {
                                        return Promise.resolve()
                                    }
                                })
                                    .then(function () {
                                        return Promise.resolve(xoUser)
                                    })
                            })
                    })
            })
            .then(function(xoUser) {
                return Promise.resolve(xoUser.id)
            })
            .catch(function (err) {
                console.log("login failed:", err);
                return Promise.reject(err);
            })
    } finally {
        client.unbind()
    }
}

ldapPlus.prototype.load = function () {
    this._xo.registerAuthenticationProvider(this._auth)
}

ldapPlus.prototype.unload = function () {
    unregisterAuthenticationProvider(this._auth)
}

ldapPlus.prototype.test = function (data) {
    console.log('the configuration is about to be tested', data)
    // TODO: test the configuration, i.e, use the main feature of the plugin and throws any errors.

}
exports.default = function (opts) {
    return new ldapPlus(opts.xo);
}
