#! /bin/bash -e

if [ "$1" = "--enable-sanitizer" ]; then
  export CFLAGS
  export LDFLAGS

  export PATH=/usr/lib/ccache:$PATH

  CFLAGS="$CFLAGS -fsanitize=address -O1 -fno-omit-frame-pointer -g"
  LDFLAGS="$LDFLAGS -fsanitize=address -fno-omit-frame-pointer -g"

  CFLAGS="$CFLAGS -Wno-format-nonliteral"
  CFLAGS="$CFLAGS -fsanitize=undefined"
  ##CFLAGS="$CFLAGS -fno-sanitize-recover"
  LDFLAGS="$LDFLAGS -fsanitize=undefined"
  #LDFLAGS="$LDFLAGS -fno-sanitize-recover"
fi

autoreconf -fvi
./configure --prefix=/tmp/usr --enable-debug
make clean
make
make check
