# Note that this is NOT a relocatable package
%define ver      2.5
%define RELEASE  1
%define rel      %{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}
%define prefix   /

Summary: Bluetooth utilities 
Name: bluez-utils
Version: %ver
Release: %rel
Copyright: GPL
Group: Applications/System
Vendor: Official Linux Bluetooth protocol stack
Packager: Sebastian Frankfurt <sf@infesto.de>
Source: http://bluez.sourceforge.net/%{name}-%{ver}.tar.gz
Patch0: %{name}-%{ver}.patch
BuildRoot: /var/tmp/%{name}-%{PACKAGE_VERSION}-root
URL: http://bluez.sourceforge.net
Docdir: %{prefix}/usr/share/doc
Requires: glibc >= 2.2.4
Requires: bluez-libs >= 2.0
BuildRequires: glibc >= 2.2.4
BuildRequires: bluez-libs >= 2.0

%description
Bluetooth utilities (bluez-utils):
	- hcitool
	- hciattach
	- hciconfig
	- hcid
	- sdpd
	- sdptool
	- ciptool
	- l2ping
	- start scripts (RedHat)
	- pcmcia configuration files

The BLUETOOTH trademarks are owned by Bluetooth SIG, Inc., U.S.A.

%changelog
* Tue Aug 13 2002 Sebastian Frankfurt <sf@infesto.de>
- Initial RPM

%prep
rm -rf $RPM_BUILD_ROOT

%setup -q

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --enable-pcmcia --prefix=%{prefix} --mandir=%{_mandir} --sysconfdir=%{_sysconfdir}
make

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT prefix=%{prefix} mandir=%{_mandir} install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)

/etc/rc.d/init.d/bluetooth
/bin/hcitool
/bin/l2ping
/bin/bluepin
/bin/rfcomm
/sbin/hciattach
/sbin/hciconfig
/sbin/hcid
/sbin/sdpd
/bin/sdptool
/bin/ciptool
%{_mandir}/man8/hciattach.8.gz
%{_mandir}/man8/hciconfig.8.gz
%{_mandir}/man5/hcid.conf.5.gz
%{_mandir}/man8/hcid.8.gz
%{_mandir}/man8/sdpd.8.gz
%{_mandir}/man1/hcitool.1.gz
%{_mandir}/man1/sdptool.1.gz
%{_mandir}/man1/ciptool.1.gz
%{_mandir}/man1/rfcomm.1.gz
%{_mandir}/man1/l2ping.1.gz
%{_sysconfdir}/bluetooth/*
%{_sysconfdir}/pcmcia/bluetooth.conf
%{_sysconfdir}/pcmcia/bluetooth

%doc AUTHORS COPYING INSTALL ChangeLog NEWS README

