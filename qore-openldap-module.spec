%define mod_ver 1.2.3
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

%if %suse_version
%define dist .opensuse%{os_maj}_%{os_min}
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
License: LGPL-2.1-or-later
Group: Development/Languages/Other
URL: http://qore.org
Source: http://prdownloads.sourceforge.net/qore/%{name}-%{version}.tar.bz2
#Source0: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: /usr/bin/env
Requires: qore-module(abi)%{?_isa} = %{module_api}
BuildRequires: gcc-c++
BuildRequires: qore-devel >= 1.12.4
BuildRequires: qore-stdlib >= 1.12.4
BuildRequires: qore >= 1.12.4
%if 0%{?suse_version} || 0%{?sles_version}
BuildRequires: openldap2-devel
%else
BuildRequires: openldap-devel
%endif
%if 0%{?el7}
BuildRequires: devtoolset-7-gcc-c++
%endif
BuildRequires: cmake >= 3.5
BuildRequires: doxygen

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

%build
%if 0%{?el7}
# enable devtoolset7
. /opt/rh/devtoolset-7/enable
%endif
export CXXFLAGS="%{?optflags}"
cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} -DCMAKE_BUILD_TYPE=RELWITHDEBINFO -DCMAKE_SKIP_RPATH=1 -DCMAKE_SKIP_INSTALL_RPATH=1 -DCMAKE_SKIP_BUILD_RPATH=1 -DCMAKE_PREFIX_PATH=${_prefix}/lib64/cmake/Qore .
make %{?_smp_mflags}
make %{?_smp_mflags} docs
sed -i 's/#!\/usr\/bin\/env qore/#!\/usr\/bin\/qore/' test/q*

%install
make DESTDIR=%{buildroot} install %{?_smp_mflags}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{module_dir}
%doc COPYING.MIT COPYING.LGPL README RELEASE-NOTES AUTHORS

%changelog
* Sat Dec 17 2022 David Nichols <david@qore.org> 1.2.3
- updated to version 1.2.3
- updated to use cmake

* Fri Apr 15 2022 David Nichols <david@qore.org> 1.2.2
- updated to v1.2.2

* Fri Jan 28 2022 David Nichols <david@qore.org> 1.2.1
- updated to v1.2.1

* Tue May 1 2018 David Nichols <david@qore.org> 1.2
- updated to v1.2

* Tue May 27 2014 David Nichols <david@qore.org> 1.1
- updated to v1.1

* Fri Dec 21 2012 David Nichols <david@qore.org> 1.0
- updated to v1.0 for initial release

* Mon Nov 5 2012 David Nichols <david@qore.org> 0.1
- initial spec file for openldap module
