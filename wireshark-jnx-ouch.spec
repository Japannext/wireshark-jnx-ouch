Summary:        JNX OUCH decoders for Wireshark
Name:           wireshark-jnx-ouch
Version:        1.6.0
Release:        2
License:        GPL+
Vendor:         Japannext Co., Ltd.
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  automake
BuildRequires:  pkgconfig
BuildRequires:  libtool
BuildRequires:  wireshark-devel

%description
JNX OUCH decoders for Wireshark

%prep
%setup -q -T -b 0 -n %{name}

%build

version_release=$(pkg-config --variable VERSION_RELEASE wireshark)
if [ -z "$version_release" ]
then
        version_release=VERSION_RELEASE=$(rpm -q wireshark-devel --qf %{VERSION} | cut -d. -f1-2)
else
        version_release=
fi

autoreconf -v -i
%configure
make $version_release

%install
make DESTDIR=%{buildroot} $version_release install

# Remove libtool archives and static libs
find %{buildroot} -type f -name "*.la" -delete

%files
%defattr(0644,root,root,0755)
%{_libdir}/wireshark/plugins/*/epan/jnx_ouch.so

%changelog

# vim:et:sw=8:
