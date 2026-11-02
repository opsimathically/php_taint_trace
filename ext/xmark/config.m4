PHP_ARG_ENABLE([xmark], [whether to enable xmark support],
  [AS_HELP_STRING([--enable-xmark], [Enable xmark extension])],
  [yes])

if test "$PHP_XMARK" != "no"; then
  PHP_NEW_EXTENSION([xmark], [xmark.c], [$ext_shared])
fi
