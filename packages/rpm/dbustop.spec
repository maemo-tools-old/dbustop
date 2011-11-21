Name: dbustop
Version: 1.0
Release: 4%{?dist}
Summary: Displays D-Bus activity in a statistical/top-like manner
Group: Development/Tools
License: GPLv2+
URL: http://www.gitorious.org/+maemo-tools-developers/maemo-tools/dbustop
Source: %{name}_%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-build
BuildRequires: pkg-config, dbus-1-devel, readline5-devel

%description
 Dbustop provides a top-like view to D-Bus activity to help understand
 interactions between services and clients and to find potential issues.
 
%prep
%setup -q -n %{name}

%build
make

%install
rm -rf %{buildroot}
make install PREFIX=/usr SYSCONFDIR=/etc DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/dbustop
%{_mandir}/man1/dbustop.1.gz
%config %{_sysconfdir}/dbus-1/system.d/%{name}.conf
%doc LICENSE

%changelog
* Thu Dec 02 2010 Eero Tamminen <eero.tamminen@nokia.com> 1.0-4
  * Bugfixes: rule matching.
  * Show command lines without arguments in interactive mode.
  * Default columns and refresh interval changed.

* Tue Nov 30 2010 Eero Tamminen <eero.tamminen@nokia.com> 1.0-3
  * Bugfixes:
    - default autorefresh interval was zero.
    - owned names were duplicated

* Wed Nov 24 2010 Eero Tamminen <eero.tamminen@nokia.com> 1.0-2
  * Fixed autorefresh mode to behave like advertised.
  * Now we remember owned names even after they are lost.

* Mon Nov 22 2010 Eero Tamminen <eero.tamminen@nokia.com> 1.0-1
  * It begins.
