Name: dbustop
Version: 1.0.4
Release: 1%{?dist}
Summary: displays D-Bus activity in a statistical/top-like manner
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
%defattr(755,root,root,-)
%{_bindir}/dbustop
%defattr(644,root,root,-)
%{_mandir}/man1/dbustop.1.gz
%config %{_sysconfdir}/dbus-1/system.d/%{name}.conf
%doc LICENSE

