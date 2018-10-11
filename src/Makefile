CC = gcc-6
BUILDDIR = build

LHTTPDSRC = api.c ip_acl.c protocol.c version.c
LHTTPDOBJ = $(patsubst %.c,$(BUILDDIR)/%.o,$(LHTTPDSRC))
LHTTPDSNM = libhttpd
LHTTPDCFL = -Wall -Wextra -fpic $(CFLAGS)

SGWSRC = auth.c commandline.c firewall.c http.c pstring.c simple_http.c centralserver.c conf.c \
fw_iptables.c httpd_thread.c reload_thread.c util.c client_list.c debug.c gateway.c ping_thread.c safe.c wd_util.c
SGWOBJ = $(patsubst %.c,$(BUILDDIR)/%.o,$(SGWSRC))
SGWEXE = wifidog
SGWCFL = -Wall -Wextra $(CFLAGS)

all: dir $(BUILDDIR)/$(LHTTPDSNM).so.0.0.0 $(BUILDDIR)/$(SGWEXE)

dir:
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/$(LHTTPDSNM).so.0.0.0: $(LHTTPDOBJ)
	$(CC) $(LHTTPDCFL) -shared -Wl,-soname,$(LHTTPDSNM).so.0 $^ -o $@
	ln -s $(LHTTPDSNM).so.0.0.0 $(BUILDDIR)/$(LHTTPDSNM).so.0
	ln -s $(LHTTPDSNM).so.0.0.0 $(BUILDDIR)/$(LHTTPDSNM).so

$(LHTTPDOBJ): $(BUILDDIR)/%.o : %.c dir
	$(CC) $(LHTTPDCFL) -c $< -o $@

$(BUILDDIR)/$(SGWEXE): $(SGWOBJ)
	$(CC) $(SGWCFL) $^ -o $@ -lpthread -lnsl -lhttpd -L $(BUILDDIR)

$(SGWOBJ): $(BUILDDIR)/%.o : %.c dir
	$(CC) $(SGWCFL) -c $< -o $@

clean:
	rm -rf $(BUILDDIR)
