#!/usr/bin/env qore
%new-style
%enable-all-warnings

%requires openldap

main();

sub main() {
    printf("%N\n", LdapClient::getInfo());

    LdapClient ldap("ldap://localhost:1389", ("binddn": "cn=Directory Manager", "password": "qoreqore"));
    printf("%N\n", ldap.search(("base": "dc=net,dc=internal", "filter": "objectClass=*")));
}
