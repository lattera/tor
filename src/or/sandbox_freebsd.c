/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file main.c
 * \brief Toplevel module. Handles signals, multiplexes between
 * connections, implements main loop, and drives scheduled events.
 *
 * For the main loop itself; see run_main_loop_once().  It invokes the rest of
 * Tor mostly through Libevent callbacks.  Libevent callbacks can happen when
 * a timer elapses, a signal is received, a socket is ready to read or write,
 * or an event is manually activated.
 *
 * Most events in Tor are driven from these callbacks:
 *  <ul>
 *   <li>conn_read_callback() and conn_write_callback() here, which are
 *     invoked when a socket is ready to read or write respectively.
 *   <li>signal_callback(), which handles incoming signals.
 *  </ul>
 * Other events are used for specific purposes, or for building more complex
 * control structures.  If you search for usage of tor_libevent_new(), you
 * will find all the events that we construct in Tor.
 *
 * Tor has numerous housekeeping operations that need to happen
 * regularly. They are handled in different ways:
 * <ul>
 *   <li>The most frequent operations are handled after every read or write
 *    event, at the end of connection_handle_read() and
 *    connection_handle_write().
 *
 *   <li>The next most frequent operations happen after each invocation of the
 *     main loop, in run_main_loop_once().
 *
 *   <li>Once per second, we run all of the operations listed in
 *     second_elapsed_callback(), and in its child, run_scheduled_events().
 *
 *   <li>Once-a-second operations are handled in second_elapsed_callback().
 *
 *   <li>More infrequent operations take place based on the periodic event
 *     driver in periodic.c .  These are stored in the periodic_events[]
 *     table.
 * </ul>
 *
 **/

#include "or.h"
#include "addressmap.h"
#include "backtrace.h"
#include "bridges.h"
#include "buffers.h"
#include "buffers_tls.h"
#include "channel.h"
#include "channeltls.h"
#include "channelpadding.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "command.h"
#include "compat_rust.h"
#include "compress.h"
#include "config.h"
#include "confparse.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "consdiffmgr.h"
#include "control.h"
#include "cpuworker.h"
#include "crypto_s2k.h"
#include "directory.h"
#include "dirserv.h"
#include "dirvote.h"
#include "dns.h"
#include "dnsserv.h"
#include "entrynodes.h"
#include "geoip.h"
#include "hibernate.h"
#include "hs_cache.h"
#include "hs_circuitmap.h"
#include "hs_client.h"
#include "keypin.h"
#include "main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "ntmain.h"
#include "onion.h"
#include "periodic.h"
#include "policies.h"
#include "protover.h"
#include "transports.h"
#include "relay.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerkeys.h"
#include "routerlist.h"
#include "routerparse.h"
#include "scheduler.h"
#include "shared_random.h"
#include "statefile.h"
#include "status.h"
#include "util_process.h"
#include "ext_orport.h"
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif
#include "memarea.h"
#include "sandbox.h"

#include <event2/event.h>

static void
init_addrinfo(void)
{
  if (! server_mode(get_options()) ||
      (get_options()->Address && strlen(get_options()->Address) > 0)) {
    /* We don't need to seed our own hostname, because we won't be calling
     * resolve_my_address on it.
     */
    return;
  }
  char hname[256];

  // host name to sandbox
  gethostname(hname, sizeof(hname));
  sandbox_add_addrinfo(hname);
}

sandbox_cfg_t*
sandbox_init_filter(void)
{
  const or_options_t *options = get_options();
  sandbox_cfg_t *cfg = sandbox_cfg_new();
  int i;

  sandbox_cfg_allow_openat_filename(&cfg,
      get_datadir_fname("cached-status"));

#define OPEN(name)                              \
  sandbox_cfg_allow_open_filename(&cfg, tor_strdup(name))

#define OPEN_DATADIR(name)                      \
  sandbox_cfg_allow_open_filename(&cfg, get_datadir_fname(name))

#define OPEN_DATADIR2(name, name2)                       \
  sandbox_cfg_allow_open_filename(&cfg, get_datadir_fname2((name), (name2)))

#define OPEN_DATADIR_SUFFIX(name, suffix) do {  \
    OPEN_DATADIR(name);                         \
    OPEN_DATADIR(name suffix);                  \
  } while (0)

#define OPEN_DATADIR2_SUFFIX(name, name2, suffix) do {  \
    OPEN_DATADIR2(name, name2);                         \
    OPEN_DATADIR2(name, name2 suffix);                  \
  } while (0)

  OPEN(options->DataDirectory);
  OPEN_DATADIR("keys");
  OPEN_DATADIR_SUFFIX("cached-certs", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-consensus", ".tmp");
  OPEN_DATADIR_SUFFIX("unverified-consensus", ".tmp");
  OPEN_DATADIR_SUFFIX("unverified-microdesc-consensus", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-microdesc-consensus", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-microdescs", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-microdescs.new", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-descriptors", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-descriptors.new", ".tmp");
  OPEN_DATADIR("cached-descriptors.tmp.tmp");
  OPEN_DATADIR_SUFFIX("cached-extrainfo", ".tmp");
  OPEN_DATADIR_SUFFIX("cached-extrainfo.new", ".tmp");
  OPEN_DATADIR("cached-extrainfo.tmp.tmp");
  OPEN_DATADIR_SUFFIX("state", ".tmp");
  OPEN_DATADIR_SUFFIX("sr-state", ".tmp");
  OPEN_DATADIR_SUFFIX("unparseable-desc", ".tmp");
  OPEN_DATADIR_SUFFIX("v3-status-votes", ".tmp");
  OPEN_DATADIR("key-pinning-journal");
  OPEN("/dev/srandom");
  OPEN("/dev/urandom");
  OPEN("/dev/random");
  OPEN("/etc/hosts");
  OPEN("/proc/meminfo");

  if (options->BridgeAuthoritativeDir)
    OPEN_DATADIR_SUFFIX("networkstatus-bridges", ".tmp");

  if (authdir_mode(options))
    OPEN_DATADIR("approved-routers");

  if (options->ServerDNSResolvConfFile)
    sandbox_cfg_allow_open_filename(&cfg,
                                tor_strdup(options->ServerDNSResolvConfFile));
  else
    sandbox_cfg_allow_open_filename(&cfg, tor_strdup("/etc/resolv.conf"));

  for (i = 0; i < 2; ++i) {
    if (get_torrc_fname(i)) {
      sandbox_cfg_allow_open_filename(&cfg, tor_strdup(get_torrc_fname(i)));
    }
  }

#define RENAME_SUFFIX(name, suffix)        \
  sandbox_cfg_allow_rename(&cfg,           \
      get_datadir_fname(name suffix),      \
      get_datadir_fname(name))

#define RENAME_SUFFIX2(prefix, name, suffix) \
  sandbox_cfg_allow_rename(&cfg,                                        \
                           get_datadir_fname2(prefix, name suffix),     \
                           get_datadir_fname2(prefix, name))

  RENAME_SUFFIX("cached-certs", ".tmp");
  RENAME_SUFFIX("cached-consensus", ".tmp");
  RENAME_SUFFIX("unverified-consensus", ".tmp");
  RENAME_SUFFIX("unverified-microdesc-consensus", ".tmp");
  RENAME_SUFFIX("cached-microdesc-consensus", ".tmp");
  RENAME_SUFFIX("cached-microdescs", ".tmp");
  RENAME_SUFFIX("cached-microdescs", ".new");
  RENAME_SUFFIX("cached-microdescs.new", ".tmp");
  RENAME_SUFFIX("cached-descriptors", ".tmp");
  RENAME_SUFFIX("cached-descriptors", ".new");
  RENAME_SUFFIX("cached-descriptors.new", ".tmp");
  RENAME_SUFFIX("cached-extrainfo", ".tmp");
  RENAME_SUFFIX("cached-extrainfo", ".new");
  RENAME_SUFFIX("cached-extrainfo.new", ".tmp");
  RENAME_SUFFIX("state", ".tmp");
  RENAME_SUFFIX("sr-state", ".tmp");
  RENAME_SUFFIX("unparseable-desc", ".tmp");
  RENAME_SUFFIX("v3-status-votes", ".tmp");

  if (options->BridgeAuthoritativeDir)
    RENAME_SUFFIX("networkstatus-bridges", ".tmp");

#define STAT_DATADIR(name)                      \
  sandbox_cfg_allow_stat_filename(&cfg, get_datadir_fname(name))

#define STAT_DATADIR2(name, name2)                                      \
  sandbox_cfg_allow_stat_filename(&cfg, get_datadir_fname2((name), (name2)))

  STAT_DATADIR(NULL);
  STAT_DATADIR("lock");
  STAT_DATADIR("state");
  STAT_DATADIR("router-stability");
  STAT_DATADIR("cached-extrainfo.new");

  {
    smartlist_t *files = smartlist_new();
    tor_log_get_logfile_names(files);
    SMARTLIST_FOREACH(files, char *, file_name, {
      /* steals reference */
      sandbox_cfg_allow_open_filename(&cfg, file_name);
    });
    smartlist_free(files);
  }

  {
    smartlist_t *files = smartlist_new();
    smartlist_t *dirs = smartlist_new();
    hs_service_lists_fnames_for_sandbox(files, dirs);
    SMARTLIST_FOREACH(files, char *, file_name, {
      char *tmp_name = NULL;
      tor_asprintf(&tmp_name, "%s.tmp", file_name);
      sandbox_cfg_allow_rename(&cfg,
                               tor_strdup(tmp_name), tor_strdup(file_name));
      /* steals references */
      sandbox_cfg_allow_open_filename(&cfg, file_name);
      sandbox_cfg_allow_open_filename(&cfg, tmp_name);
    });
    SMARTLIST_FOREACH(dirs, char *, dir, {
      /* steals reference */
      sandbox_cfg_allow_stat_filename(&cfg, dir);
    });
    smartlist_free(files);
    smartlist_free(dirs);
  }

  {
    char *fname;
    if ((fname = get_controller_cookie_file_name())) {
      sandbox_cfg_allow_open_filename(&cfg, fname);
    }
    if ((fname = get_ext_or_auth_cookie_file_name())) {
      sandbox_cfg_allow_open_filename(&cfg, fname);
    }
  }

  SMARTLIST_FOREACH_BEGIN(get_configured_ports(), port_cfg_t *, port) {
    if (!port->is_unix_addr)
      continue;
    /* When we open an AF_UNIX address, we want permission to open the
     * directory that holds it. */
    char *dirname = tor_strdup(port->unix_addr);
    if (get_parent_directory(dirname) == 0) {
      OPEN(dirname);
    }
    tor_free(dirname);
    sandbox_cfg_allow_chmod_filename(&cfg, tor_strdup(port->unix_addr));
    sandbox_cfg_allow_chown_filename(&cfg, tor_strdup(port->unix_addr));
  } SMARTLIST_FOREACH_END(port);

  if (options->DirPortFrontPage) {
    sandbox_cfg_allow_open_filename(&cfg,
                                    tor_strdup(options->DirPortFrontPage));
  }

  // orport
  if (server_mode(get_options())) {

    OPEN_DATADIR2_SUFFIX("keys", "secret_id_key", ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "secret_onion_key", ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "secret_onion_key_ntor", ".tmp");
    OPEN_DATADIR2("keys", "secret_id_key.old");
    OPEN_DATADIR2("keys", "secret_onion_key.old");
    OPEN_DATADIR2("keys", "secret_onion_key_ntor.old");

    OPEN_DATADIR2_SUFFIX("keys", "ed25519_master_id_secret_key", ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "ed25519_master_id_secret_key_encrypted",
                         ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "ed25519_master_id_public_key", ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "ed25519_signing_secret_key", ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "ed25519_signing_secret_key_encrypted",
                         ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "ed25519_signing_public_key", ".tmp");
    OPEN_DATADIR2_SUFFIX("keys", "ed25519_signing_cert", ".tmp");

    OPEN_DATADIR2_SUFFIX("stats", "bridge-stats", ".tmp");
    OPEN_DATADIR2_SUFFIX("stats", "dirreq-stats", ".tmp");

    OPEN_DATADIR2_SUFFIX("stats", "entry-stats", ".tmp");
    OPEN_DATADIR2_SUFFIX("stats", "exit-stats", ".tmp");
    OPEN_DATADIR2_SUFFIX("stats", "buffer-stats", ".tmp");
    OPEN_DATADIR2_SUFFIX("stats", "conn-stats", ".tmp");
    OPEN_DATADIR2_SUFFIX("stats", "hidserv-stats", ".tmp");

    OPEN_DATADIR("approved-routers");
    OPEN_DATADIR_SUFFIX("fingerprint", ".tmp");
    OPEN_DATADIR_SUFFIX("hashed-fingerprint", ".tmp");
    OPEN_DATADIR_SUFFIX("router-stability", ".tmp");

    OPEN("/etc/resolv.conf");

    RENAME_SUFFIX("fingerprint", ".tmp");
    RENAME_SUFFIX2("keys", "secret_onion_key_ntor", ".tmp");
    RENAME_SUFFIX2("keys", "secret_id_key", ".tmp");
    RENAME_SUFFIX2("keys", "secret_id_key.old", ".tmp");
    RENAME_SUFFIX2("keys", "secret_onion_key", ".tmp");
    RENAME_SUFFIX2("keys", "secret_onion_key.old", ".tmp");
    RENAME_SUFFIX2("stats", "bridge-stats", ".tmp");
    RENAME_SUFFIX2("stats", "dirreq-stats", ".tmp");
    RENAME_SUFFIX2("stats", "entry-stats", ".tmp");
    RENAME_SUFFIX2("stats", "exit-stats", ".tmp");
    RENAME_SUFFIX2("stats", "buffer-stats", ".tmp");
    RENAME_SUFFIX2("stats", "conn-stats", ".tmp");
    RENAME_SUFFIX2("stats", "hidserv-stats", ".tmp");
    RENAME_SUFFIX("hashed-fingerprint", ".tmp");
    RENAME_SUFFIX("router-stability", ".tmp");

    RENAME_SUFFIX2("keys", "ed25519_master_id_secret_key", ".tmp");
    RENAME_SUFFIX2("keys", "ed25519_master_id_secret_key_encrypted", ".tmp");
    RENAME_SUFFIX2("keys", "ed25519_master_id_public_key", ".tmp");
    RENAME_SUFFIX2("keys", "ed25519_signing_secret_key", ".tmp");
    RENAME_SUFFIX2("keys", "ed25519_signing_cert", ".tmp");

    sandbox_cfg_allow_rename(&cfg,
             get_datadir_fname2("keys", "secret_onion_key"),
             get_datadir_fname2("keys", "secret_onion_key.old"));
    sandbox_cfg_allow_rename(&cfg,
             get_datadir_fname2("keys", "secret_onion_key_ntor"),
             get_datadir_fname2("keys", "secret_onion_key_ntor.old"));

    STAT_DATADIR("keys");
    OPEN_DATADIR("stats");
    STAT_DATADIR("stats");
    STAT_DATADIR2("stats", "dirreq-stats");

    consdiffmgr_register_with_sandbox(&cfg);
  }

  init_addrinfo();

  return cfg;
}
