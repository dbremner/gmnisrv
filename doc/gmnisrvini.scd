gmnisrv.ini(5)

# NAME

*gmnisrv.ini* - configuration file for *gmnisrv*(1)

# SYNTAX

*gmnisrv.ini* is an INI file. Each line is either a key/value pair, or a section
heading. Key/value pairs are specified as key=value, and sections as [section].

# CONFIGURATION KEYS

The meaning of the key depends on the section. Anonymous keys (prior to the
first [section] directive) are used to specify parameters for the daemon itself.
Sections whose name is prefixed with ":", e.g. [:tls], are sub-categories of
the daemon configuration. Otherwise, section names refer to the hostnames of
domains serviced by the *gmnisrv* daemon.

## ANONYMOUS KEYS

*listen*
	A space-separated list of addresses that the daemon shall bind to. Each
	address shall take the format *address*:*port*. If :*port* is omitted,
	1965 (the default Gemini port) is presumed. To specify an IPv6 address,
	enclose it in *[]*, e.g. *[::]*.


## TLS KEYS

The following keys are accepted under the *[:tls]* section:

*store*
	Path to the certificate store on disk. This should be a persistent
	directory writable by the daemon. The daemon manages its own
	certificates - no user intervention is required, except in the case of
	moving the daemon to another host, in which case the certificate store
	must be copied to the new host.

*organization*
	An optional key used during certificate generation. Fill this in with
	the name of the organization responsible for the host and it will be
	filled in as the X.509 /O name.

## HOST KEYS

Hosts that *gmnisrv* is to serve shall be defined in *gmnisrv.ini* by
introducing config sections named after each host to provide service for. The
following keys apply:

*root*
	Configures the path on disk from which files shall be served for this
	host.

*index*
	Configures the name of the index file which shall be served in the event
	that a request for this host does not include the filename part.
	Defaults to "index.gmi".

*autoindex*
	"on" to enable the auto-index feature, which presents clients with a
	list of files in the requested directory when an index file cannot be
	found. Off by default.
