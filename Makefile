.POSIX:
.SUFFIXES:
OUTDIR=.build
include $(OUTDIR)/config.mk
include $(OUTDIR)/cppcache

gmnisrv: $(gmnisrv_objects)
	@printf 'CCLD\t$@\n'
	@$(CC) $(LDFLAGS) -o $@ $(gmnisrv_objects) $(LIBS)

.SUFFIXES: .c .o .scd .1

.c.o:
	@printf 'CC\t$@\n'
	@touch $(OUTDIR)/cppcache
	@grep $< $(OUTDIR)/cppcache >/dev/null || \
		$(CPP) $(CFLAGS) -MM -MT $@ $< >> $(OUTDIR)/cppcache
	@$(CC) -c $(CFLAGS) -o $@ $<

.scd.1:
	@printf 'SCDOC\t$@\n'
	@$(SCDOC) < $< > $@

# TODO: Docs
docs:
	@true

clean:
	@rm -f gmnisrv $(gmnisrv_objects)

distclean: clean
	@rm -rf "$(OUTDIR)"

install: all
	mkdir -p $(BINDIR)
	install -Dm755 gmnisrv $(DESTDIR)$(BINDIR)/gmnisrv

.PHONY: clean distclean docs install
