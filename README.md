# gmnisrv

gmnisrv is a simple [Gemini](https://gemini.circumlunar.space) protocol server.

## Installation

```
$ mkdir build
$ cd build
$ ../configure --prefix=/usr
$ make
# make install
```

## Configuration

By default it reads from `/etc/gmnisrv.ini`, but this can be changed by passing
the `-C` flag to the `gmnisrv` daemon. A sample config.ini is provided at
`/usr/share/gmnisrv/gmnisrv.ini`:

```
# Space-separated list of hosts
listen=0.0.0.0:1965 [::]:1965

[:tls]
# Path to store certificates on disk
store=/var/lib/gemini/certs

# Optional details for new certificates
organization=gmnisrv user

[localhost]
root=/var/www
```

For full details on gmnisrv configuration, consult the *gmnisrv*(5) manual page.

## Usage

See *gmnisrv*(1).
