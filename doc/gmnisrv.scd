gmnisrv(1)

# NAME

gmnisrv - serve clients over the gemini protocol

# SYNPOSIS

*gmnisrv* [-C _path_]

# DESCRIPTION

*gmnisrv* is a daemon which serves network clients over the gemini protocol. It
requires a config file; by default this shall be read from /etc/gmnisrv.ini
unless the installation was configured with a different SYSCONFDIR or the user
provides the -C flag.

# OPTIONS

*-C* _path_
	Specifies an alternate path to read the config file from.

# LOG FORMAT

Server diagnostics and client errors are printed to *stderr* in an unspecified
format. Nominal client logging is printed to *stdout*, with each of the
following fields in order, separated by whitespace:

- Client IP
- Request hostname
- Request path
- Service time
- Response body size in bytes
- Response status
- Response meta

# SEE ALSO

*gmnisrv.ini*(5)
