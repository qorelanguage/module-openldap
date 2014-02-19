MNAME=openldap

QC_LdapClient.cpp: QC_LdapClient.qpp
	qpp $<

GENERATED_SOURCES = QC_LdapClient.cpp
CLEANFILES = $(GENERATED_SOURCES)

if COND_SINGLE_COMPILATION_UNIT
OPENLDAP_SOURCES = single-compilation-unit.cpp
single-compilation-unit.cpp: $(GENERATED_SOURCES)
else
OPENLDAP_SOURCES = openldap-module.cpp QC_LdapClient.cpp
nodist_openldap_la_SOURCES = $(GENERATED_SOURCES)
endif

lib_LTLIBRARIES = openldap.la
openldap_la_SOURCES = $(OPENLDAP_SOURCES)
openldap_la_LDFLAGS = -module -avoid-version ${OPENLDAP_LIBS} ${MODULE_LDFLAGS}

INCLUDES = -I$(top_srcdir)/include $(OPENLDAP_CPPFLAGS)

AM_CPPFLAGS=$(QORE_CPPFLAGS)

if COND_PROFILE
AM_CXXFLAGS=-g -pg
else
if COND_DEBUG
AM_CXXFLAGS=-g
endif
endif

if COND_MINGW
RM_OTHER=$(DESTDIR)$(libdir)/$(MNAME).dll.a
endif

install-exec-hook:
	mv $(DESTDIR)$(libdir)/$(MNAME).$(MODULE_SUFFIX) $(DESTDIR)$(libdir)/$(MNAME)-api-$(MODULE_API).qmod
	$(RM) $(DESTDIR)$(libdir)/$(MNAME).la $(DESTDIR)$(libdir)/$(MNAME).a $(RM_OTHER)

