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

DLLLOCAL const QoreStringNode* check_hash_key(const QoreHashNode& h, const char* key, const char* err, ExceptionSink *xsink);

class AttrListHelper {
protected:
   char** attrs;
   size_t size;
   
public:
   DLLLOCAL AttrListHelper(const QoreListNode* attrl, ExceptionSink* xsink) : attrs(0), size(0) {
      // convert list to attribute list
      if (!attrl || !attrl->empty())
         return;
      
      size = attrl->size();
      
      attrs = new char*[attrl->size() + 1];
      ConstListIterator li(attrl);
      while (li.next()) {
         QoreStringValueHelper str(li.getValue(), QCS_UTF8, xsink);
         if (*xsink)
            return;
         attrs[li.index()] = new char[str->size() + 1];
         strcpy(attrs[li.index()], str->getBuffer());
      }
      attrs[li.max()] = 0;
   }
   
   DLLLOCAL ~AttrListHelper() {
      if (!attrs)
         return;
      
      for (unsigned i = 0; i < size; ++i)
         delete attrs[i];
      delete [] attrs;
   }
   
   DLLLOCAL char** operator*() const {
      return attrs;
   }
};

struct QoreLDAPAPIInfoHelper : public LDAPAPIInfo {
   bool initialized;

   DLLLOCAL QoreLDAPAPIInfoHelper() : initialized(false) {
      ldapai_info_version = LDAP_API_INFO_VERSION;
   }

   DLLLOCAL ~QoreLDAPAPIInfoHelper() {
      if (!initialized)
         return;

      ldap_memfree(ldapai_vendor_name);
      if (ldapai_extensions)
         ber_memvfree((void **)ldapai_extensions);
   }

   DLLLOCAL int init() {
      assert(!initialized);
      int ec = ldap_get_option(0, LDAP_OPT_API_INFO, this);
      if (!ec)
         initialized = true;
      return ec;
   }
};

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

      return initIntern(xsink);
   }

   DLLLOCAL int initIntern(const QoreStringNode& uristr, ExceptionSink* xsink) {
      assert(!ldp);
      assert(!uri);
      uri = uristr.stringRefSelf();
      return initIntern(xsink);
   }

   DLLLOCAL int initIntern(ExceptionSink* xsink) {
      if (checkLdapError(ldap_initialize(&ldp, uri->getBuffer()), xsink))
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

      const QoreStringNode* binddn = check_hash_key(bindh, "binddn", "LDAP-BIND-ERROR", xsink);
      if (!binddn)
	 return -1;

      const QoreStringNode* password = check_hash_key(bindh, "password", "LDAP-BIND-ERROR", xsink);
      if (!password)
	 return -1;

      QoreStringValueHelper bstr(binddn, QCS_UTF8, xsink);
      if (*xsink)
         return -1;

      QoreStringValueHelper pstr(password, QCS_UTF8, xsink);
      if (*xsink)
         return -1;

      struct berval passwd = {0, 0};
      passwd.bv_val = (char*)pstr->getBuffer();
      passwd.bv_len = pstr->size();
      /*
      passwd.bv_val = ber_strdup(password);
      ON_BLOCK_EXIT(ber_memfree, passwd.bv_val);
      passwd.bv_len = strlen(passwd.bv_val);
      */

      if (checkLdapError(ldap_sasl_bind_s(ldp, bstr->getBuffer(), LDAP_SASL_SIMPLE, &passwd, 0, 0, 0), xsink))
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

   DLLLOCAL QoreHashNode* search(ExceptionSink* xsink, const QoreStringNode* base, int scope, const QoreStringNode* filter, const QoreListNode* attrl = 0, bool attrsonly = false) {
      // convert strings to UTF-8 if necessary
      QoreStringValueHelper bstr(base, QCS_UTF8, xsink);
      if (*xsink)
         return 0;

      QoreStringValueHelper fstr(filter, QCS_UTF8, xsink);
      if (*xsink)
         return 0;
      
      AutoLocker al(m);
      if (checkValidIntern("search", xsink))
	 return 0;

      // get attribute list
      AttrListHelper attrs(attrl, xsink);
      if (*xsink)
         return 0;

      LDAPMessage* res = 0;
      if (checkLdapError(ldap_search_ext_s(ldp, bstr->empty() ? 0 : bstr->getBuffer(), scope, fstr->empty() ? 0 : fstr->getBuffer(), *attrs, (int)attrsonly, 0, 0, 0, 0, &res), xsink))
         return 0;
      ON_BLOCK_EXIT(ldap_msgfree, res);
      
      ReferenceHolder<QoreHashNode> h(new QoreHashNode, xsink);

      //printd(5, "LdapClient::search() results: %d entries: %d\n", ldap_count_messages(ldp, res), ldap_count_entries(ldp, res));

      LDAPMessage* e = ldap_first_entry(ldp, res);
      for (int i = 0; e; ++i, e = ldap_next_entry(ldp, e)) {
         ReferenceHolder<QoreHashNode> he(new QoreHashNode, xsink);

         /*
         for (LDAPMessage* msg = ldap_first_message(ldp, e); msg; msg = ldap_next_message(ldp, msg)) {
            printd(0, "LdapClient::search() message type: %d entries: %d\n", ldap_msgtype(msg), ldap_count_entries(ldp, msg));
            if (ldap_msgtype(msg) == LDAP_RES_SEARCH_RESULT) {
            }
         }
         */

         BerElement* ber;
         char* attr = ldap_first_attribute(ldp, e, &ber);
         for (; attr; attr = ldap_next_attribute(ldp, e, ber)) {
            struct berval** vals;
            //printd(5, "LdapClient::search() attribute: %s\n", attr);

            ReferenceHolder<> aval(xsink);
            QoreListNode* al = 0;
            if ((vals = ldap_get_values_len(ldp, e, attr))) {
               for (unsigned i = 0; vals[i]; ++i) {
                  //printd(5, "LdapClient::search (%ld) %s\n", vals[i]->bv_len, vals[i]->bv_val );
                  QoreStringNode *avstr = new QoreStringNode(vals[i]->bv_val, vals[i]->bv_len, QCS_UTF8);
                  if (!i)
                     aval = avstr;
                  else {
                     if (i == 1) {
                        al = new QoreListNode;
                        al->push(aval.release());
                        aval = al;
                     }
                     al->push(avstr);
                  }
               }

               ber_bvecfree(vals);
            }
            
            he->setKeyValue(attr, aval.release(), 0);
            ldap_memfree(attr);
         }
         if (ber)
            ber_free(ber, 0);

         char* p = ldap_get_dn(ldp, e);
         h->setKeyValue(p, he.release(), 0);
         ldap_memfree(p);
      }

      return h.release();
   }

   DLLLOCAL QoreStringNode* getUriStr() const {
      assert(uri);
      return uri->stringRefSelf();
   }

   DLLLOCAL static QoreStringNode* checkLibrary() {
      QoreLDAPAPIInfoHelper ai;
      int ec = ai.init();
      if (ec)
	 return new QoreStringNodeMaker("the openldap library returned error code %d: %s to the ldap_get_option(LDAP_OPT_API_INFO) function", ec, ldap_err2string(ec));

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

      QoreLDAPAPIInfoHelper ai;
      if (ai.init())
	 return h;

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

