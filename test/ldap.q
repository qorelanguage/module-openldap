#!/usr/bin/env qore
%new-style
%enable-all-warnings

%requires openldap

main();

const Defaults = (
    "uri": "ldap://localhost:389",
    "filter": "objectClass=*",
    );

const opts = (
    "uri": "H,uri=s",
    "bind": "D,binddn=s",
    "pass": "w,passwd=s",
    "base": "b,basedn=s",
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

    printf("%N\n", ldap.search(opts.("base", "filter", "attributes")));
}

sub usage() {
    printf("usage: %s [options] filter
  -b,--basedn=ARG   base dn for search
  -D,--binddn=ARG   bind DN
  -H,--uri=ARG      LDAP Uniform Resource Identifier(s)
  -w,--passwd=ARG   bind password (for simple authentication)
  -i,--info         show ldap library info and exit
  -h,--help         this help text
", get_script_name());
    exit(0);
}
