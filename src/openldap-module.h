/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  openldap-module.h
  
  Qore Programming Language

  Copyright 2003 - 2010 David Nichols

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

#ifndef _QORE_OPENLDAP_MODULE_H
#define _QORE_OPENLDAP_MODULE_H

#include <config.h>

#include <qore/Qore.h>

#include <ldap.h>

#include <map>
#include <string>

typedef std::map<std::string, int> strintmap_t;

class ModMap : public strintmap_t {
public:
   DLLLOCAL ModMap() {
      insert(ModMap::value_type("add", LDAP_MOD_ADD));
      insert(ModMap::value_type("delete", LDAP_MOD_DELETE));
      insert(ModMap::value_type("replace", LDAP_MOD_REPLACE));
   }

   DLLLOCAL int get(const char* mod) const {
      const ModMap::const_iterator i = find(mod);
      return i == end() ? -1 : i->second;
   }
};

DLLLOCAL extern ModMap modmap;

#endif
