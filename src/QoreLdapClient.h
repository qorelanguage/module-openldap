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

#include <memory>

// default ldap operation timeout in milliseconds
#define QORE_LDAP_DEFAULT_TIMEOUT_MS 60000

// default ldap protocol version
#define QORE_LDAP_DEFAULT_PROTOCOL 3

template<typename T>
DLLLOCAL const T* check_hash_key(ExceptionSink *xsink, const QoreHashNode& h, const char* key, const char* err, const char* hash_name = 0) {
   const AbstractQoreNode* p = h.getKeyValue(key);
   if (is_nothing(p)) {
      if (hash_name)
         xsink->raiseException(err, "no value for '%s' key present in %s", key, hash_name);
      return 0;
   }

   if (p->getType() != T::getStaticTypeCode()) {
      xsink->raiseException(err, "'%s' key is not type '%s' but is type '%s'", key, T::getStaticTypeName(), get_type_name(p));
      return 0;
   }
   return reinterpret_cast<const T*>(p);
}

template <typename T>
class LdapListHelper {
protected:
   T* l;
   size_t len;

   DLLLOCAL virtual int addElement(const ConstListIterator& li, ExceptionSink* xsink) = 0;

   DLLLOCAL LdapListHelper() : l(0), len(0) {
   }
   
   DLLLOCAL int init(const QoreListNode* ql, ExceptionSink* xsink) {
      // convert list to attribute list
      if (!ql || ql->empty())
         return 0;
      
      len = ql->size();
      
      l = new T[ql->size() + 1];
      ConstListIterator li(ql);
      while (li.next()) {
         if (addElement(li, xsink)) {
            len = li.index() + 1;
            return -1;
         }
      }
      // terminate list with a 0
      l[li.max()] = 0;
      return 0;
   }

public:
   DLLLOCAL virtual ~LdapListHelper() {
   }

   DLLLOCAL T* operator*() const {
      return l;
   }

   DLLLOCAL size_t size() const {
      return len;
   }
};

class AttrListHelper : public LdapListHelper<char*> {
protected:
   DLLLOCAL virtual int addElement(const ConstListIterator& li, ExceptionSink* xsink) {
      QoreStringValueHelper str(li.getValue(), QCS_UTF8, xsink);
      if (*xsink)
         return -1;
      char*& e = l[li.index()];
      e = new char[str->size() + 1];
      strcpy(e, str->getBuffer());
      return 0;
   }
   
public:
   DLLLOCAL AttrListHelper(const QoreListNode* attrl, ExceptionSink* xsink) : LdapListHelper<char*>() {
      init(attrl, xsink);
   }

   DLLLOCAL virtual ~AttrListHelper() {
      if (!l)
         return;
      
      for (unsigned i = 0; i < len; ++i)
         delete [] l[i];
      delete [] l;
   }
};

class QoreLDAPMod : public LDAPMod {
protected:
   DLLLOCAL int assignString(qore_size_t i, const AbstractQoreNode* p, ExceptionSink* xsink) {
      QoreStringValueHelper str(p, QCS_UTF8, xsink);
      if (*xsink)
         return -1;

      mod_values[i] = new char[str->size() + 1];
      strcpy(mod_values[i], str->getBuffer());
      return 0;
   }
   
public: 
   DLLLOCAL QoreLDAPMod(int n_mod_op, const char* attr, const AbstractQoreNode* p, ExceptionSink* xsink) {
      mod_op = n_mod_op;
      mod_type = (char*)attr;
      mod_values = 0;

      qore_type_t t = get_node_type(p);
      if (t == NT_NOTHING)
         return;

      if (t == NT_LIST) {
         const QoreListNode* l = reinterpret_cast<const QoreListNode*>(p);
         if (l->empty())
            return;

         ConstListIterator li(l);
         while (li.next()) {
            if (assignString(li.index(), li.getValue(), xsink)) {
               mod_values[li.index() + 1] = 0;
               return;
            }
         }
         return;
      }
      mod_values = new char*[2];
      assignString(0, p, xsink);
      mod_values[1] = 0;
   }

   DLLLOCAL ~QoreLDAPMod() {
      if (mod_op & LDAP_MOD_BVALUES) {
         for (berval** p = mod_bvalues; p; ++p)
            delete *p;
         delete mod_bvalues;
      }
      else {
         for (char** p = mod_values; p; ++p)
            delete *p;
         delete mod_values;
      }
   }
};

class ModListHelper : public LdapListHelper<QoreLDAPMod*> {
protected:
   DLLLOCAL virtual int addElement(const ConstListIterator& li, ExceptionSink* xsink) {
      const AbstractQoreNode* p = li.getValue();
      if (get_node_type(p) != NT_HASH) {
         xsink->raiseException("LDAP-MODIFY-ERROR", "element %d/%d (starting from 0) is type '%s'; expecting 'hash'", li.index(), li.max(), get_type_name(p));
         return -1;
      }
      const QoreHashNode* h = reinterpret_cast<const QoreHashNode*>(p);
      const QoreStringNode* mod = check_hash_key<QoreStringNode>(xsink, *h, "mod", "LDAP-MODIFY-ERROR", "ldap modification hash");
      if (!mod)
         return -1;

      int mod_op = modmap.get(mod->getBuffer());
      if (mod_op == -1) {
         xsink->raiseException("LDAP-MODIFY-ERROR", "element %d/%d (starting with 0) don't know how to process modification action '%s' (expecting one of 'add', 'delete', 'replace')", li.index(), li.max(), mod->getBuffer());
         return -1;
      }

      const QoreStringNode* attr = check_hash_key<QoreStringNode>(xsink, *h, "attr", "LDAP-MODIFY-ERROR", "ldap modification hash");
      if (!attr)
         return -1;

      p = h->getKeyValue("value");

      QoreLDAPMod*& e = l[li.index()];
      e = new QoreLDAPMod(mod_op, attr->getBuffer(), p, xsink);

      return *xsink ? -1 : 0;
   }
   
public:
   DLLLOCAL ModListHelper(const QoreListNode* ql, ExceptionSink* xsink) : LdapListHelper<QoreLDAPMod*>() {
      init(ql, xsink);
   }

   DLLLOCAL virtual ~ModListHelper() {
      if (!l)
         return;
      
      for (unsigned i = 0; i < len; ++i)
         delete l[i];
      delete [] l;
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

struct TimeoutHelper : public timeval {
   DLLLOCAL TimeoutHelper(int ms) {
      if (ms < 0)
         ms = 0;
      tv_sec = ms / 1000;
      tv_usec = (ms - (tv_sec * 1000)) * 1000;
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

   void doLdapError(const char* f, int ec, ExceptionSink* xsink) const {
      QoreStringNode* desc = new QoreStringNode("openldap server ");
      if (uri)
	 desc->sprintf("'%s' ", uri->getBuffer());
      desc->sprintf("returned error code %d", ec);
      desc->sprintf(" to %s(): %s", f, ldap_err2string(ec), xsink);
      xsink->raiseException("LDAP-ERROR", desc);
   }

   int checkLdapError(const char* f, int ec, ExceptionSink* xsink) const {
      //printd(5, "QoreLdapClient::checkLdapError() %s() rc: %d\n", f, ec);
      if (ec == LDAP_SUCCESS)
	 return 0;
      doLdapError(f, ec, xsink);
      return -1;
   }

   int checkLdapResult(int ec, ExceptionSink* xsink) const {
      //printd(5, "QoreLdapClient::checkLdapResult() rc: %d\n", ec);
      // timeout
      if (!ec) {
         doLdapError("ldap_result", LDAP_TIMEOUT, xsink);
         return -1;
      }
      if (ec == -1) {
         doLdapError("ldap_result", ec, xsink);
         return -1;
      }
      return 0;
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

   DLLLOCAL int initIntern(ExceptionSink* xsink, const QoreStringNode& uristr, int iv = QORE_LDAP_DEFAULT_PROTOCOL) {
      assert(!ldp);
      assert(!uri);
      uri = uristr.stringRefSelf();
      return initIntern(xsink, iv);
   }

   DLLLOCAL int initIntern(ExceptionSink* xsink, int iv = QORE_LDAP_DEFAULT_PROTOCOL) {
      if (checkLdapError("ldap_initialize", ldap_initialize(&ldp, uri->getBuffer()), xsink))
	 return -1;

      // set protocol version
      if (ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &iv)) {
	 xsink->raiseException("LDAP-ERROR", "failed to set LDAP protocol v%d; ldap_set_option(LDAP_OPT_PROTOCOL_VERSION) failed", iv);
	 return -1;
      }

      // set restart option
      if (ldap_set_option(ldp, LDAP_OPT_RESTART, LDAP_OPT_ON)) {
	 xsink->raiseException("LDAP-ERROR", "failed to set LDAP restart option; ldap_set_option(LDAP_OPT_RESTART) failed");
	 return -1;
      }

      return 0;
   }

   DLLLOCAL int bindInitIntern(ExceptionSink* xsink, const char* m, const QoreHashNode& bindh, int timeout_ms = -1) {
      assert(ldp);

      const QoreStringNode* password = check_hash_key<QoreStringNode>(xsink, bindh, "password", "LDAP-BIND-ERROR");

      const QoreStringNode* binddn = check_hash_key<QoreStringNode>(xsink, bindh, "binddn", "LDAP-BIND-ERROR");
      if (!binddn) {
         if (password)
            xsink->raiseException("LDAP-BIND-ERROR", "password given but no bind DN given for bind");
	 return -1;
      }

      QoreStringValueHelper bstr(binddn, QCS_UTF8, xsink);
      if (*xsink)
         return -1;

      struct berval passwd = {0, 0};
      if (password) {
         QoreStringValueHelper pstr(password, QCS_UTF8, xsink);
         if (*xsink)
            return -1;

         passwd.bv_val = (char*)pstr->getBuffer();
         passwd.bv_len = pstr->size();
         /*
         passwd.bv_val = ber_strdup(password);
         ON_BLOCK_EXIT(ber_memfree, passwd.bv_val);
         passwd.bv_len = strlen(passwd.bv_val);
         */
      }

      int msgid;

      if (checkLdapError("ldap_sasl_bind", ldap_sasl_bind(ldp, bstr->getBuffer(), LDAP_SASL_SIMPLE, &passwd, 0, 0, &msgid), xsink))
         return -1;
      
      LDAPMessage* result = 0;
      TimeoutHelper timeout(timeout_ms);

      if (checkLdapResult(ldap_result(ldp, msgid, LDAP_MSG_ALL, timeout_ms < 0 ? 0 : &timeout, &result), xsink))
         return -1;
      
      ldap_msgfree(result);
      return 0;
   }

public:
   DLLLOCAL QoreLdapClient(const QoreStringNode* uristr, const QoreHashNode* opth, ExceptionSink* xsink) : ldp(0), uri(0), bh(0) {
      //printd(5, "QoreLdapClient::QoreLdapClient() this: %p uri: '%s' opth: %p\n", this, uristr->getBuffer(), opth);

      const AbstractQoreNode* p = opth->getKeyValue("protocol");
      int iv = p ? p->getAsInt() : 0;
      if (!iv)
         iv = QORE_LDAP_DEFAULT_PROTOCOL;

      if (initIntern(xsink, *uristr, iv))
	 return;
      if (opth) {
         bindInitIntern(xsink, "constructor", *opth);
         if (*xsink)
            return;

         int timeout_ms = getMsZeroInt(opth->getKeyValue("timeout"));
         if (!timeout_ms)
            timeout_ms = QORE_LDAP_DEFAULT_TIMEOUT_MS;

         TimeoutHelper timeout(timeout_ms);

         if (ldap_set_option(ldp, LDAP_OPT_TIMEOUT, &timeout)) {
            xsink->raiseException("LDAP-ERROR", "failed to set LDAP timeout to %d ms; ldap_set_option(LDAP_OPT_TIMEOUT) failed", timeout_ms);
            return;
         }

         p = opth->getKeyValue("no-referrals");
         bool refp = p ? p->getAsBool() : 0;
         if (refp && ldap_set_option(ldp, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) {
            xsink->raiseException("LDAP-ERROR", "failed to disable LDAP referrals; ldap_set_option(LDAP_OPT_REFERRALS) failed");
            return;
         }

         //printd(0, "QoreLdapClient::QoreLdapClient() set default timeout to %d ms\n", timeout_ms);
      }
      
   }
   
   DLLLOCAL QoreLdapClient(const QoreLdapClient& old, ExceptionSink* xsink) : ldp(0), uri(0), bh(0) {
      AutoLocker al(old.m);
      if (old.checkValidIntern("constructor", xsink))
	 return;

      // get protocol version
      int iv = 0;
      ldap_get_option(old.ldp, LDAP_OPT_PROTOCOL_VERSION, &iv);
      if (!iv)
         iv = QORE_LDAP_DEFAULT_PROTOCOL;

      if (initIntern(xsink, *old.uri, iv))
	 return;

      if (old.bh && bindInitIntern(xsink, "copy", *old.bh))
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

      return bindInitIntern(xsink, "bind", bindh);
   }

   DLLLOCAL QoreHashNode* search(ExceptionSink* xsink, const QoreStringNode* base, int scope, const QoreStringNode* filter, const QoreListNode* attrl = 0, bool attrsonly = false, int timeout_ms = -1) {
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

      int msgid;
      if (checkLdapError("ldap_search_ext", ldap_search_ext(ldp, bstr->empty() ? 0 : bstr->getBuffer(), scope, fstr->empty() ? 0 : fstr->getBuffer(), *attrs, (int)attrsonly, 0, 0, 0, 0, &msgid), xsink))
         return 0;

      LDAPMessage* res = 0;
      TimeoutHelper timeout(timeout_ms);

      if (checkLdapResult(ldap_result(ldp, msgid, LDAP_MSG_ALL, timeout_ms < 0 ? 0 : &timeout, &res), xsink))
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

