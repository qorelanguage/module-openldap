/* indent-tabs-mode: nil -*- */
/*
  openldap Qore module

  Copyright (C) 2012 - 2014 David Nichols, all rights reserved

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

#include "openldap-module.h"

#include "QoreLdapClient.h"

static QoreStringNode *openldap_module_init();
static void openldap_module_ns_init(QoreNamespace *rns, QoreNamespace *qns);
static void openldap_module_delete();

// qore module symbols
DLLEXPORT char qore_module_name[] = "openldap";
DLLEXPORT char qore_module_version[] = PACKAGE_VERSION;
DLLEXPORT char qore_module_description[] = "openldap module";
DLLEXPORT char qore_module_author[] = "David Nichols";
DLLEXPORT char qore_module_url[] = "http://qore.org";
DLLEXPORT int qore_module_api_major = QORE_MODULE_API_MAJOR;
DLLEXPORT int qore_module_api_minor = QORE_MODULE_API_MINOR;
DLLEXPORT qore_module_init_t qore_module_init = openldap_module_init;
DLLEXPORT qore_module_ns_init_t qore_module_ns_init = openldap_module_ns_init;
DLLEXPORT qore_module_delete_t qore_module_delete = openldap_module_delete;
#ifdef _QORE_HAS_QL_MIT
DLLEXPORT qore_license_t qore_module_license = QL_MIT;
#else
DLLEXPORT qore_license_t qore_module_license = QL_LGPL;
#endif
DLLEXPORT char qore_module_license_str[] = "MIT";

DLLLOCAL QoreClass* initLdapClientClass(QoreNamespace& ns);

// modify action map
ModMap modmap;

static QoreNamespace OLNS("OpenLdap");

static QoreStringNode* openldap_module_init() {
   // this also serves to initialize the library in a single-threaded way
   QoreStringNode* err = QoreLdapClient::checkLibrary();
   if (err)
      return err;

   OLNS.addSystemClass(initLdapClientClass(OLNS));

   return 0;
}

static void openldap_module_ns_init(QoreNamespace* rns, QoreNamespace* qns) {
   qns->addNamespace(OLNS.copy());
}

static void openldap_module_delete() {
}
