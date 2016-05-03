
AC_INIT([noise-c], [0.0.1])
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_RANLIB
AC_PROG_LEX
AC_PROG_YACC
AC_PATH_PROG(DOXYGEN, doxygen)

AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(ws2_32, [_head_libws2_32_a])

AC_SUBST([WARNING_FLAGS],[-Wall])

AC_CONFIG_FILES([Makefile
include/Makefile
include/noise/Makefile
include/noise/protocol/Makefile
src/Makefile
src/protocol/Makefile
src/protobufs/Makefile
src/protoc/Makefile
tests/Makefile
tests/unit/Makefile
tests/vector/Makefile
tests/performance/Makefile
examples/Makefile
examples/echo/Makefile
examples/echo/echo-client/Makefile
examples/echo/echo-keygen/Makefile
examples/echo/echo-server/Makefile
doc/Makefile])
AC_OUTPUT
