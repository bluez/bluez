# Note that this is NOT a relocatable package
%define ver      2.5
%define RELEASE  1
%define rel      %{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}
%define prefix   /usr

Summary: Bluetooth libraries
Name: bluez-libs
Version: %ver
Release: %rel
Copyright: GPL
Group: Applications/System
Vendor: Official Linux Bluetooth protocol stack
Packager: Sebastian Frankfurt <sf@infesto.de>
Source: http://bluez.sourceforge.net/%{name}-%{ver}.tar.gz
BuildRoot: /var/tmp/%{name}-%{PACKAGE_VERSION}-root
URL: http://bluez.sourceforge.net
Docdir: %{prefix}/share/doc
Requires: glibc >= 2.2.4
BuildRequires: glibc >= 2.2.4

%description
Bluetooth libraries.

The BLUETOOTH trademarks are owned by Bluetooth SIG, Inc., U.S.A.

%changelog
* Tue Aug 13 2002 Sebastian Frankfurt <sf@infesto.de>
- Initial RPM

%prep
rm -rf $RPM_BUILD_ROOT
#rm -rf /usr/src/redhat/BUILD/*

%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{prefix}
make

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT%{prefix} install

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)

/usr/include/bluetooth/*
/usr/lib/libbluetooth*
/usr/lib/libsdp*

%doc AUTHORS COPYING INSTALL ChangeLog NEWS README

