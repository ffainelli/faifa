dnl --------------------------------------------------------------------------
dnl PA_ADD_CFLAGS()
dnl
dnl Attempt to add the given option to CFLAGS, if it doesn't break compilation
dnl --------------------------------------------------------------------------
AC_DEFUN(PA_ADD_CFLAGS,
[AC_MSG_CHECKING([if $CC accepts $1])
 pa_add_cflags__old_cflags="$CFLAGS"
 CFLAGS="$CFLAGS $1"
 AC_TRY_LINK([#include <stdio.h>],
 [printf("Hello, World!\n");],
 AC_MSG_RESULT([yes]),
 AC_MSG_RESULT([no])
 CFLAGS="$pa_add_cflags__old_cflags")])

dnl ------------------------------------------------------------------------
dnl  PA_WITH_BOOL
dnl
dnl  PA_WITH_BOOL(option, default, help, enable, disable)
dnl
dnl  Provides a more convenient way to specify --with-option and
dnl  --without-option, with a default.  default should be either 0 or 1.
dnl ------------------------------------------------------------------------
AC_DEFUN(PA_WITH_BOOL,
[AC_ARG_WITH([$1], [$3],
if test ["$withval"] != no; then
[$4]
else
[$5]
fi,
if test [$2] -ne 0; then
[$4]
else
[$5]
fi)])
