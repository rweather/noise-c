
AC_INIT([noise-c], [0.0.1])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_RANLIB
AC_PROG_LEX
AC_PROG_YACC
AC_PATH_PROG(DOXYGEN, doxygen)

dnl Determine the default Ed448-Goldilocks architecture to use.
AC_CHECK_DECL([__x86_64__])
AC_CHECK_SIZEOF(void *)
if test "x$ac_cv_have_decl___x86_64__" = "xyes" ; then
    ED448_DEFAULT_ARCH=arch_x86_64
else
    if test "x$ac_cv_sizeof_void_p" = "x8" ; then
        ED448_DEFAULT_ARCH=arch_ref64
    else
        ED448_DEFAULT_ARCH=arch_32
    fi
fi

AC_ARG_WITH([ed448-arch],
    [AS_HELP_STRING([--with-ed448-arch=ARCH],
                    [specify the Ed448-Goldilocks architecture])],
    [],
    [with_ed448_arch=${ED448_DEFAULT_ARCH}])

AC_CHECK_LIB(rt, clock_gettime)

dnl Try to detect winsock2 on mingw32/64 systems.
AC_CHECK_LIB(ws2_32, [_head_libws2_32_a])
AC_CHECK_LIB(ws2_32, [_head_lib32_libws2_32_a])
AC_CHECK_LIB(ws2_32, [_head_lib64_libws2_32_a])

AC_CHECK_FUNCS([poll])

AX_PTHREAD([LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"],[])

AC_SUBST([WARNING_FLAGS],[-Wall])
AC_SUBST([GOLDILOCKS_ARCH],[$with_ed448_arch])

AC_CONFIG_FILES([Makefile
include/Makefile
include/noise/Makefile
include/noise/protocol/Makefile
include/noise/keys/Makefile
src/Makefile
src/protocol/Makefile
src/protobufs/Makefile
src/keys/Makefile
tests/Makefile
tests/unit/Makefile
tests/vector/Makefile
tests/vector-gen/Makefile
tests/performance/Makefile
tools/Makefile
tools/keytool/Makefile
tools/protoc/Makefile
examples/Makefile
examples/echo/Makefile
examples/echo/echo-client/Makefile
examples/echo/echo-keygen/Makefile
examples/echo/echo-server/Makefile
doc/Makefile])

AC_ARG_WITH([libsodium],
  [AS_HELP_STRING([--with-libsodium],
    [use libsodium for crypto @<:@default=check@:>@])],
  [],
  [with_libsodium=no])
AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl],
    [use openssl for crypto @<:@default=check@:>@])],
  [],
  [with_openssl=no])

PKG_PROG_PKG_CONFIG
AS_IF([test -n "$PKG_CONFIG"], [
  AS_CASE(["$with_libsodium"],
    [yes], [PKG_CHECK_MODULES_STATIC([libsodium], [libsodium], [HAVE_LIBSODIUM=1])],
    [no], [HAVE_LIBSODIUM=0],
    [PKG_CHECK_MODULES_STATIC([libsodium], [libsodium], [HAVE_LIBSODIUM=1], [HAVE_LIBSODIUM=0])])
  AM_CONDITIONAL([USE_LIBSODIUM], [test "$with_libsodium" != no -a "$HAVE_LIBSODIUM" -eq 1])

  AS_CASE(["$with_openssl"],
    [yes], [PKG_CHECK_MODULES_STATIC([openssl], [openssl], [HAVE_OPENSSL=1])],
    [no], [HAVE_OPENSSL=0],
    [PKG_CHECK_MODULES_STATIC([openssl], [openssl], [HAVE_OPENSSL=1], [HAVE_OPENSSL=0])])
  AM_CONDITIONAL([USE_OPENSSL], [test "$with_openssl" != no -a "$HAVE_OPENSSL" -eq 1])
], [
  AC_MSG_WARN([Can't find pkg-config. Using built-in reference crypto backend.])
  AM_CONDITIONAL([USE_LIBSODIUM],[false])
  AM_CONDITIONAL([USE_OPENSSL],[false])
])

AC_ARG_ENABLE(asan, AC_HELP_STRING([--enable-asan],
			[Compile with Address Sanitizer]), [
	if (test "${enableval}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=address";
		LDFLAGS="$LDFLAGS -fsanitize=address"
	fi
])

AC_ARG_ENABLE(ubsan, AC_HELP_STRING([--enable-ubsan],
			[Compile with Undefined Behavior Sanitizer]), [
	if (test "${enableval}" = "yes"); then
		CFLAGS="$CFLAGS -fsanitize=undefined";
		LDFLAGS="$LDFLAGS -fsanitize=undefined"
	fi
])

AC_OUTPUT
