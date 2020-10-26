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

## ROUTING KEYS

To configure *gmnisrv* to service requests, routing keys must be defined. The
name of the configuration section is used to determine what kinds of requests it
configures.

The format of the section name is the _hostname_ to be serviced, followed by a
token which defines the routing strategy, and a string whose format is specific
to each routing strategy. The token and match string may be omitted
(i.e. [_hostname_] alone), which implies path routing against "/".

|] *:*
:< Route by path prefix. The URL path is compared to "_string_/".
|  *=*
:  Exact match. The URL path must exactly match the string.
|  *~*
:  Regular expression routing. The string is a JavaScript-compatible regular
   expression which is tested against the URL path.

Some example section names and examples of matching paths:

|[ *[example.org:/foo]*
:< /foo, /foo/bar, /foo/bar/baz
|  *[example.org=/foo.txt]*
:  /foo.txt
|  *[example.org~/[a-z]+\\.(png|jpg|webp)*
:  /foo.png, /bar.webp

Routes should be ordered from least to most specific. The matching algorithm
attempts to match the URL against each route in reverse order, and chooses the
first route which matches.

Within each routing section, the following keys are used to configure how
*gmnisrv* will respond to matching requests:

*root*
	Configures the path on disk from which files shall be served for this
	host. If using path prefix matching, the prefix is trimmed, so if
	example.org/foo/bar.txt is requested and matches *[example.org:/foo]*,
	"bar.txt" will be appended to the root to form the file path.

*index*
	Configures the name of the index file which shall be served in the event
	that a request for this host does not include the filename part.
	Defaults to "index.gmi".

*autoindex*
	"on" to enable the auto-index feature, which presents clients with a
	list of files in the requested directory when an index file cannot be
	found. Off by default.

*cgi*
	"on" to enable CGI support. *root* must also be configured. See "CGI
	Support" for details.

# CGI Support

*gmnisrv* supports a limited version of CGI, compatible with the Jetforce
server. It is not a faithful implementation of RFC 3875, but is sufficient for
most of the needs of Gemini servers.

Set *cgi=on* for a route configuration to enable CGI for that route and set
*root* to the path where the CGI scripts are found. If a client requests a
script, it will be executed, and must print a Gemini response (including status
code and meta) to stdout.

The following environment variables will be set:

[[ *Variable*
:[ *Example*
:< *Description*
|  *GATEWAY_INTERFACE*
:  GCI/1.1
:  CGI version
|  *SERVER_PROTOCOL*
:  GEMINI
:  The server protocol
|  *SERVER_SOFTWARE*
:  gmnisrv/0.0.0
:  The gmnisrv server name and version
|  *GEMINI_URL*
:  See [1]
:  The URL requested by the client
|  *SCRIPT_NAME*
:  /cgi-bin/foo.sh
:  The portion of the URL referring to the script name.
|  *PATH_INFO*
:  /bar
:  The remainder of the path following *SCRIPT_NAME*.
|  *QUERY_STRING*
:  hello=world
:  The query string portion of the URL.
|  *SERVER_NAME*, *HOSTNAME*
:  example.org
:  The server host name.
|  *SERVER_PORT*
:  1965
:  The server port number.
|  *REMOTE_HOST*, *REMOTE_ADDR*
:  10.10.0.2
:  The clients IP address.
|  *TLS_CIPHER*
:  TLS_AES_256_GCM_SHA384
:  The negotiated TLS cipher.
|  *TLS_VERSION*
:  TLSv1.3
:  The negotiated TLS version.

\[1]: gemini://example.org/cgi-bin/foo.sh/bar?hello=world

The exit status of the script is ignored.
