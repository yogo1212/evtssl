pkgname=libevtssl-git
pkgver=0.6_11_gc20ad45
pkgrel=1
pkgdesc="produce sockets for use libevent"
arch=('x86_64' 'armv7h' 'aarch64')
url="https://github.com/yogo1212/evtssl"
provides=('libevtssl')
conflicts=('libevtssl')
license=('Unlicense')
makedepends=('git' 'gcc' 'make')
depends=('libevent')
source=(git://github.com/yogo1212/evtssl.git)
sha256sums=('SKIP')

pkgver() {
  cd evtssl

	git describe --tags | tr - _
}

build() {
  cd evtssl

  make all
}

package() {
	cd evtssl

  make install ROOT="$pkgdir/" usr=usr/
}
