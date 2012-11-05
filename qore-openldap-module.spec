%define mod_ver 0.1
%define module_api %(qore --latest-module-api 2>/dev/null)
%define module_dir %{_libdir}/qore-modules

%if 0%{?sles_version}

%define dist .sles%{?sles_version}

%else
%if 0%{?suse_version}

# get *suse release major version
%define os_maj %(echo %suse_version|rev|cut -b3-|rev)
# get *suse release minor version without trailing zeros
%define os_min %(echo %suse_version|rev|cut -b-2|rev|sed s/0*$//)

%if %suse_version > 1010
%define dist .opensuse%{os_maj}_%{os_min}
%else
%define dist .suse%{os_maj}_%{os_min}
%endif

%endif
%endif

# see if we can determine the distribution type
%if 0%{!?dist:1}
%define rh_dist %(if [ -f /etc/redhat-release ];then cat /etc/redhat-release|sed "s/[^0-9.]*//"|cut -f1 -d.;fi)
%if 0%{?rh_dist}
%define dist .rhel%{rh_dist}
%else
%define dist .unknown
%endif
%endif

Summary: OPENLDAP module for Qore
Name: qore-openldap-module
Version: %{mod_ver}
Release: 1%{dist}
License: LGPL
Group: Development/Languages
URL: http://qore.org
Source: http://prdownloads.sourceforge.net/qore/%{name}-%{version}.tar.bz2
#Source0: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: /usr/bin/env
Requires: qore-module-api-%{module_api}
BuildRequires: gcc-c++
BuildRequires: qore-devel >= 0.8.6
BuildRequires: libopenldap-devel
BuildRequires: qore

%description
This package contains the openldap module for the Qore Programming Language.

This module exposes functionality from the openldap library as a Qore API.

%if 0%{?suse_version}
%debug_package
%endif

%package doc
Summary: Documentation and examples for the Qore openldap module
Group: Development/Languages

%description doc
This package contains the HTML documentation and example programs for the Qore
openldap module.

%files doc
%defattr(-,root,root,-)
%doc docs/openldap test

%prep
%setup -q
./configure RPM_OPT_FLAGS="$RPM_OPT_FLAGS" --prefix=/usr --disable-debug

%build
%{__make}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{module_dir}
mkdir -p $RPM_BUILD_ROOT/usr/share/doc/qore-openldap-module
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{module_dir}
%doc COPYING README RELEASE-NOTES ChangeLog AUTHORS 

%changelog
* Mon Nov 5 2012 David Nichols <david@qore.org> 0.1
- initial spec file for openldap module
