.POSIX:
.SUFFIXES:
OUTDIR=.build
include $(OUTDIR)/config.mk
include $(OUTDIR)/cppcache

gmnisrv: $(gmnisrv_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) -o $@ $(gmnisrv_objects) $(LIBS)

doc/gmnisrv.1: doc/gmnisrv.scd
doc/gmnisrvini.5: doc/gmnisrvini.scd

.SUFFIXES: .c .o .scd .1 .5

.c.o:
	@printf 'CC\t$@\n'
	@touch $(OUTDIR)/cppcache
	@grep $< $(OUTDIR)/cppcache >/dev/null || \
		$(CPP) $(CFLAGS) -MM -MT $@ $< >> $(OUTDIR)/cppcache
	@$(CC) -c $(CFLAGS) -o $@ $<

.scd.1:
	@printf 'SCDOC\t$@\n'
	@$(SCDOC) < $< > $@

.scd.5:
	@printf 'SCDOC\t$@\n'
	@$(SCDOC) < $< > $@

docs: doc/gmnisrv.1 doc/gmnisrvini.5

clean:
	@rm -f gmnisrv $(gmnisrv_objects) doc/*.1 doc/*.5

distclean: clean
	@rm -rf "$(OUTDIR)"

install: all
	mkdir -p \
		$(DESTDIR)$(BINDIR) \
		$(DESTDIR)$(SHAREDIR)/gmnisrv \
		$(DESTDIR)$(MANDIR)/man5 \
		$(DESTDIR)$(MANDIR)/man1
	install -Dm755 gmnisrv $(DESTDIR)$(BINDIR)/gmnisrv
	install -Dm644 $(SRCDIR)/config.ini $(DESTDIR)$(SHAREDIR)/gmnisrv/gmnisrv.ini
	install -Dm644 doc/gmnisrv.1 $(DESTDIR)$(MANDIR)/man1/gmnisrv.1
	install -Dm644 doc/gmnisrvini.5 $(DESTDIR)$(MANDIR)/man5/gmnisrv.ini.5

.PHONY: clean distclean docs install
