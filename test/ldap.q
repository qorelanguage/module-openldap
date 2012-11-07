#!/usr/bin/env qore
%new-style
%enable-all-warnings

%requires openldap

main();

const Defaults = (
    "uri": "ldap://localhost:389",
    "filter": "objectClass=*",
    );

const ScopeMap = (
    "base": LDAP_SCOPE_BASE,
    "one": LDAP_SCOPE_ONELEVEL,
    "sub": LDAP_SCOPE_SUBTREE,
    "children": LDAP_SCOPE_CHILDREN,
    );

const opts = (
    "uri": "H,uri=s",
    "bind": "D,binddn=s",
    "pass": "w,passwd=s",
    "base": "b,basedn=s",
    "scope": "s,scope=s",
    "info": "i,info",
    "help": "h,help",
    );

sub main() {
    GetOpt g(opts);
    hash opts = g.parse3(\ARGV);
    if (opts.help)
	usage();

    if (opts.info) {
	printf("%N\n", LdapClient::getInfo());
	exit(0);
    }

    if (opts.scope) {
	*int scope = ScopeMap.(opts.scope);
	if (!exists scope) {
	    stderr.printf("%s: invalid scope %y (expecing one of %y)", get_script_name(), opts.scope, ScopeMap.keys());
	    exit(1);
	}
	opts.scope = scope;
    }

    opts.filter = ARGV[0] ? ARGV[0] : Defaults.filter;
    opts.attributes = ARGV[1];
    hash lopt;
    if (opts.binddn)
	lopt += ("binddn": opts.binddn);
    if (opts.pass)
	lopt += ("password": opts.password);
    if (!opts.uri)
	opts.uri = Defaults.uri;

    LdapClient ldap(opts.uri, lopt);

    printf("%N\n", ldap.search(opts.("base", "filter", "attributes", "scope")));
}

sub usage() {
    printf("usage: %s [options] filter
  -b,--basedn=ARG   base dn for search
  -D,--binddn=ARG   bind DN
  -H,--uri=ARG      LDAP Uniform Resource Identifier(s)
  -s,--scope=ARG    the search scope, one of base, one, sub, or children
  -w,--passwd=ARG   bind password (for simple authentication)
  -i,--info         show ldap library info and exit
  -h,--help         this help text
", get_script_name());
    exit(0);
}
