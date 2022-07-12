/*
 * header file to be used by applications.
 */

int printu(const char *s, ...);
int exit(int code);

// added for lab1_challenge1_backtrace.
// predeclaration.
int print_backtrace(int depth);
