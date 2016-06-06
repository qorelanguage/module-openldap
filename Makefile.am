modverdir = $(libdir)/$(mymodverdir)

AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

noinst_HEADERS = src/QoreLdapClient.h

EXTRA_DIST = COPYING.MIT COPYING.LGPL AUTHORS README \
	RELEASE-NOTES \
	src/QC_LdapClient.qpp \
	src/openldap-module.h \
	test/qldapadd \
	test/qldapmodify \
	test/qldapdelete \
	test/qldapsearch \
	test/qldappasswd \
	qore-openldap-module.spec

ACLOCAL_AMFLAGS=-I m4

if COND_DOXYGEN
DOX = openldap
DOXYGEN_OUTPUT=docs/openldap/html
DOXYFILES = docs/doxyfile docs/mainpage.doxygen
DOXYFILES_SRC = docs/doxyfile.tmpl docs/qlib/Doxyfile.tmpl docs/footer_template.html
QDX = qdx
DX_CLEANFILES = ${DOXYFILES}

docs/openldap/html: $(DOXYFILES)
	cd docs; $(DOXYGEN_CMD) doxyfile;
	$(QDX) --post docs/openldap/html/*html
	$(QDX) --post docs/openldap/html/search/*html

docs/mainpage.doxygen: docs/mainpage.doxygen.tmpl
	$(QDX) -d $< $@

docs/doxyfile: docs/doxyfile.tmpl
	sed s/__VERSION__/${VERSION}/ $< > $@

doxygen-doc: $(DOXYGEN_OUTPUT)

EXTRA_DIST += $(DOXYGEN_OUTPUT)

html-local: $(DOXYGEN_OUTPUT)

install-html-local:
	for dox in $(DOX); do $(MKDIR_P) $(DESTDIR)$(datadir)/$(PACKAGE)/docs/$$dox/html/search; done
	for dir in $(DOXYGEN_OUTPUT); do \
	   for f in $$dir/*; do if [ -f $$f ]; then $(INSTALL_DATA) $$f $(DESTDIR)$(datadir)/$(PACKAGE)/$$dir; fi; done; \
	   for f in $$dir/search/*; do $(INSTALL_DATA) $$f $(DESTDIR)$(datadir)/$(PACKAGE)/$$dir/search; done; \
	done

clean-local:
	$(RM) -rf $(DOXYGEN_OUTPUT)

uninstall-local:
	$(RM) -rf $(DESTDIR)$(datadir)/$(PACKAGE)/docs

else
doxygen-doc:
	echo no doxygen support
endif

mostlyclean-local:
	rm -rf ${DOXYGEN_OUTPUT} ${DX_CLEANFILES}

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
