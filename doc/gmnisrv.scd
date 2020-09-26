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

# SEE ALSO

*gmnisrv.ini*(5)
