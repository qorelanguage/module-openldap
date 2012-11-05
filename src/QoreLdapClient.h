/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  QoreLdapClient.h

  Qore Programming Language

  Copyright 2012 David Nichols

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _QORE_QORELDAPCLIENT_H

#define _QORE_QORELDAPCLIENT_H

#include <ldap.h>

#include <errno.h>
#include <string.h>

DLLLOCAL const char* check_hash_key(const QoreHashNode& h, const char* key, const char* err, ExceptionSink *xsink);

// the c++ object
class QoreLdapClient : public AbstractPrivateData {
protected:
   // ldap context
   LDAP* ldp;
   // mutual-exclusion lock
   mutable QoreThreadLock m;
   // saved URI
   QoreStringNode* uri;
   // saved bind parameters
   QoreHashNode* bh;

   void doLdapError(int ec, ExceptionSink* xsink) const {
      QoreStringNode* desc = new QoreStringNode;
      desc->sprintf("openldap returned error code %d", ec);
      if (uri)
	 desc->sprintf(" with URI '%s'", uri->getBuffer());
      desc->sprintf(": %s", ldap_err2string(ec));
      xsink->raiseException("LDAP-ERROR", desc);
   }
   
   int checkLdapError(int ec, ExceptionSink* xsink) const {
      if (ec == LDAP_SUCCESS)
	 return 0;
      doLdapError(ec, xsink);
      return -1;
   }

   DLLLOCAL int checkValidIntern(const char* m, ExceptionSink* xsink) const {
      if (!ldp) {
	 xsink->raiseException("LDAP-NO-CONTEXT", "cannot execute LdapClient::%s(); the LdapClient object has been destroyed or the session context has been unbound", m);
	 return -1;
      }
	 
      return 0;
   }

   DLLLOCAL int unbindIntern(ExceptionSink* xsink) {
      ldap_unbind_ext_s(ldp, 0, 0);
      ldp = 0;

      return initIntern(*uri, xsink);
   }

   DLLLOCAL int initIntern(const QoreStringNode& uristr, ExceptionSink* xsink) {
      assert(!ldp);
      assert(!uri);
      uri = uristr.stringRefSelf();
      if (checkLdapError(ldap_initialize(&ldp, uristr.getBuffer()), xsink))
	 return -1;

      // set protocol version 3
      int iv = 3;
      if (ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &iv)) {
	 xsink->raiseException("LDAP-ERROR", "failed to set LDAP protocol v3; ldap_set_option(LDAP_OPT_PROTOCOL_VERSION) failed");
	 return -1;
      }

      return 0;
   }

   DLLLOCAL int bindInitIntern(const char* m, const QoreHashNode& bindh, ExceptionSink* xsink) {
      assert(ldp);

      const char* binddn = check_hash_key(bindh, "binddn", "LDAP-BIND-ERROR", xsink);
      if (!binddn)
	 return -1;

      const char* password = check_hash_key(bindh, "password", "LDAP-BIND-ERROR", xsink);
      if (!password) {
	 
	 return -1;
      }

      struct berval passwd = {0, 0};
      passwd.bv_val = ber_strdup(password);
      passwd.bv_len = strlen(passwd.bv_val);

      if (checkLdapError(ldap_sasl_bind_s(ldp, binddn, LDAP_SASL_SIMPLE, &passwd, 0, 0, 0), xsink))
	 return -1;

      return 0;
   }

public:
   DLLLOCAL QoreLdapClient(const QoreStringNode* uristr, const QoreHashNode* bindh, ExceptionSink* xsink) : ldp(0), uri(0), bh(0) {
      //printd(5, "QoreLdapClient::QoreLdapClient() this: %p uri: '%s' bindh: %p\n", this, uristr->getBuffer(), bindh);
      if (initIntern(*uristr, xsink))
	 return;
      if (bindh && bindInitIntern("constructor", *bindh, xsink))
	 return;
   }
   
   DLLLOCAL QoreLdapClient(const QoreLdapClient& old, ExceptionSink* xsink) : ldp(0), uri(0), bh(0) {
      AutoLocker al(old.m);
      if (old.checkValidIntern("constructor", xsink))
	 return;

      if (initIntern(*old.uri, xsink))
	 return;

      if (old.bh && bindInitIntern("copy", *old.bh, xsink))
	 return;
   }

   DLLLOCAL ~QoreLdapClient() {
      assert(!ldp);
      assert(!uri);
      assert(!bh);
   }

   DLLLOCAL int destructor(ExceptionSink* xsink) {
      AutoLocker al(m);
      if (ldp) {
	 ldap_unbind_ext_s(ldp, 0, 0);
	 ldp = 0;
      }

      if (uri) {
	 uri->deref();
	 uri = 0;
      }

      if (bh) {
	 bh->deref(xsink);
	 bh = 0;
      }

      return 0;
   }
   
   DLLLOCAL int bind(const QoreHashNode& bindh, ExceptionSink* xsink) {
      AutoLocker al(m);
      if (checkValidIntern("bind", xsink))
	 return -1;

      if (unbindIntern(xsink))
	 return -1;

      return bindInitIntern("bind", bindh, xsink);
   }

   DLLLOCAL static QoreStringNode* checkLibrary() {
      LDAPAPIInfo ai;
      ai.ldapai_info_version = LDAP_API_INFO_VERSION;
      int ec = ldap_get_option(0, LDAP_OPT_API_INFO, &ai);
      if (ec)
	 return new QoreStringNodeMaker("the openldap library returned error code %d: %s to the ldap_get_option(LDAP_OPT_API_INFO) function", ec, ldap_err2string(ec));

      // delete memory on exit
      ON_BLOCK_EXIT(ldap_memfree, ai.ldapai_vendor_name);
      ON_BLOCK_EXIT(ber_memvfree, (void **)ai.ldapai_extensions);

      if (ai.ldapai_info_version != LDAP_API_INFO_VERSION)
	 return new QoreStringNodeMaker("cannot load the openldap module due to a library info version mismatch; module was compiled with API info version %d but the library provides API info version %d", LDAP_API_INFO_VERSION, ai.ldapai_info_version);
	 
      if (ai.ldapai_api_version != LDAP_API_VERSION)
	 return new QoreStringNodeMaker("cannot load the openldap module due to a library version mismatch; module was compiled with API version %d but the library provides API version %d", LDAP_API_VERSION, ai.ldapai_api_version);

      if (strcmp(ai.ldapai_vendor_name, LDAP_VENDOR_NAME))
	 return new QoreStringNodeMaker("cannot load the openldap module due to a library vendor name mismatch; module was compiled with a library from '%s' but the library is now running with a library from '%s'", LDAP_VENDOR_NAME, ai.ldapai_vendor_name);

      if (ai.ldapai_vendor_version != LDAP_VENDOR_VERSION)
	 return new QoreStringNodeMaker("cannot load the openldap module due to a library vendor version mismatch; module was compiled with API vendor version %d but the library provides API vendor version %d", LDAP_VENDOR_VERSION, ai.ldapai_vendor_version);

      return 0;
   }

   DLLLOCAL static QoreHashNode* getInfo() {
      QoreHashNode* h = new QoreHashNode;

      LDAPAPIInfo ai;
      ai.ldapai_info_version = LDAP_API_INFO_VERSION;
      if (ldap_get_option(0, LDAP_OPT_API_INFO, &ai))
	 return h;

      // delete memory on exit
      ON_BLOCK_EXIT(ldap_memfree, ai.ldapai_vendor_name);
      ON_BLOCK_EXIT(ber_memvfree, (void **)ai.ldapai_extensions);

      h->setKeyValue("ApiVersion", new QoreBigIntNode(ai.ldapai_api_version), 0);
      h->setKeyValue("ProtocolVersion", new QoreBigIntNode(ai.ldapai_protocol_version), 0);
      h->setKeyValue("VendorName", new QoreStringNode(ai.ldapai_vendor_name), 0);
      h->setKeyValue("VendorVersion", new QoreBigIntNode(ai.ldapai_vendor_version), 0);
      
      QoreListNode* el = new QoreListNode;
      for (unsigned i = 0; ai.ldapai_extensions[i]; ++i)
	 el->push(new QoreStringNode(ai.ldapai_extensions[i]));
      
      h->setKeyValue("Extensions", el, 0);
      return h;
   }
};

#endif

