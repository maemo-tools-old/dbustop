#if 0 /*
exec c++ -g -Wall -rdynamic -O0 -std=c++0x \
	`pkg-config --cflags --libs dbus-1` \
	-lreadline "$0"
#*/
#endif
/*
 * This file is part of dbustop.
 *
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Akos PASZTORY <akos.pasztory@nokia.com>
 */
#define TESTS 0
#define _GNU_SOURCE 1

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <list>
#include <vector>
#include <utility>
#include <tr1/unordered_map>
#include <tr1/unordered_set>

#include <dbus/dbus.h>
#include <readline/readline.h>
#include <readline/history.h>

using std::list;
using std::vector;
using std::string;
using std::map;
using std::multimap;
using std::set;
using std::pair;
using std::make_pair;
using std::swap;
using std::tr1::unordered_map;
using std::tr1::unordered_multimap;
using std::tr1::unordered_set;

/* =================
 * Macro definitions
 * ================= */

#define DBUS_SERVICE "org.freedesktop.DBus"
#define DBUS_PATH    "/"
#define DBUS_IF	     "org.freedesktop.DBus"
#define BUS_CALL_MSG(member)						\
	dbus_message_new_method_call(DBUS_SERVICE, DBUS_PATH,		\
				     DBUS_IF, member)

#define LEVEL_DEBUG 3

#define log(LEVEL, ...)						     \
	for (bool __log = Verbosity >= LEVEL; __log; __log = !__log) \
		do_log(LEVEL, ##__VA_ARGS__)

#define fatal(...) log(0, ##__VA_ARGS__)
#define debug(...) log(LEVEL_DEBUG, ##__VA_ARGS__)

// NOTE: args are evaluated multiple times
#define foreach(ITER, CONTAINER)					\
	for (auto ITER = CONTAINER.begin(), ITER##__end = CONTAINER.end(); \
	     ITER != ITER##__end; ++ITER)

#if TESTS
# define MAIN	   not_main
# define TEST_MAIN main
#else
# define MAIN	   main
# define TEST_MAIN test_main
#endif

#if 1
#define RL_PROMPT						\
	"\001\033[1;35m\002"					\
	"** "							\
	"\001\033[0;39m\002"
#else
#define RL_PROMPT "** "
#endif

/* ==========
 * Data types
 * ========== */

struct Client;
struct BusConnection;

// A Matchrule always has a shorter lifetime than its owner
struct Matchrule {
	static Matchrule *create(char const *rule);

	bool applies(DBusMessage *msg) const;
	void dump(FILE *stream) const;

	Client *owner;

	enum {
		HasType	     = 1 << 0,
		HasSender    = 1 << 1,
		HasDest	     = 1 << 2,
		HasPath	     = 1 << 3,
		HasInterface = 1 << 4,
		HasMember    = 1 << 5,
		HasArgs	     = 1 << 6,
	};

	unsigned int flags;

	int type;
	string sender;
	string dest;
	string path;
	string interface;
	string member;
	map<int, string> args;
};

struct Client {
	//Client(BusConnection *bus);
	Client(BusConnection *bus, char const *uniq);
	~Client();
	void dump(FILE *stream) const;

	// process AddMatch and RemoveMatch messages also during the initial
	// exploration
	void add_match(char const *rule_str);
	void remove_match(char const *rule_str);
	void add_owned_name(char const *name);
	void remove_owned_name(char const *name);
	void croak();

	void reset_counters(bool all);
	char const *displayname() const;
	void refresh_cmdline() const;

	pid_t pid;
	mutable string cmdline;
	BusConnection *bus;
	string unique_name;
	bool exited;
	unsigned long last_activity;

	set<string> owned_names;
	set<string> ever_owned_names;
	list<Matchrule *> match_rules;

	struct MsgDetail {
		unsigned long count;
		unsigned long bytes;
	};

	struct DetailKey {
		string peer;
		string msg;
		friend bool operator<(DetailKey const &a,
				      DetailKey const &b);
		DetailKey(string const &peer,
			  string const &msg) :
			peer(peer), msg(msg)
			{}
	};

	// TODO some more descriptive ds instead of pair...
	// also, map or unsorted map?

	// (sender/dest, msgkind) -> (count, bytes)
	//typedef map<pair<string, string>, MsgDetail> Details;
	typedef map<DetailKey, MsgDetail> Details;

	struct Counters {
		unsigned long out_messages;
		unsigned long out_calls;
		unsigned long out_signals;
		unsigned long out_bytes;
		unsigned long in_messages;
		unsigned long in_calls;
		unsigned long in_matches;
		unsigned long in_bytes;
		unsigned long wakeups;

		Details sent;
		Details received;
	};

	Counters current;
	Counters total;
};

struct Matchmaker {
	void dump(FILE *stream) const;
	void add_rule(Matchrule *rule);
	void remove_rule(Matchrule *rule);
	void remove_client(Client *client);

	static unsigned long hash_rule(Matchrule *rule);
	static unsigned long hash_msg(DBusMessage *msg);

	// return list of clients matching msg
	list<Client *> matching_clients(Client *target, DBusMessage *msg) const;

	unordered_multimap<unsigned long, Matchrule *> rules;
	list<Matchrule *> rules2;
};

struct Statistics {
	unsigned long total_messages;
	unsigned long total_bytes;
	unsigned long total_wakeups;
};

struct BusConnection {
	DBusBusType bustype;
	DBusConnection *conn;
	int busfd;
	char const *ourname;
	char prefix;

	Matchmaker matchmaker;
	unordered_map<string, Client *> peers;
	unordered_map<string, Client *> destinations;

	BusConnection(DBusBusType bt);
	DBusMessage *call_bus(DBusMessage *call, int loglevel = 0);
	void connect();
	void shutdown();
	void explore();
	void add_peer(char const *unique_name, bool query_matchrules);
	void remove_peer(char const *unique_name);
	void fill_daemon_info();
};

typedef void (*Command_fn)(char const *args);
struct Command {
	Command(char const *name, char const *args,
		Command_fn fn, char const *desc, char const *help);

	void print_brief() const;
	void print_help() const;

	char const *name;
	char const *args;
	Command_fn func;
	char const *desc;
	char const *help;
};

struct Column {
	char const *header;
	char const *headerfmt;
	char const *fmt;
	char const *desc;
};

enum {
	ViewActive = 0,
	ViewAll = 1,
	ViewSelection = 2,

	ViewLast,
};

/* =================
 * Private variables
 * ================= */

// all connected buses
static vector<BusConnection *> Buses;
static Statistics Stats;
static bool Monitor;
static unsigned long Last_event;
static bool Ignore_replies = false;

// UI related
static unordered_set<Client *> Selection;
static bool Alive = true;
static bool Autorefresh;
static timeval Trefresh, Tnext;
static bool Interactive;
static pid_t Giveway_pid;
struct winsize Winsize;
static int Verbosity = 1;
static bool Quiet;
static bool Keep_stdin;
static char *Control_fifo;
static int Fifo = -1;
static bool Stdin_eof = false;
static map<string, Command> Commands;
static int Use_view = ViewActive;
static bool Show_totals;
static bool Gone_last = true;
static unsigned long Last_reset;

// ColumnId and Columns must match
// XXX put it into a map...
enum ColumnId {
	CPid,
	CUniqueName,
	CName,
	CNrMatchrules,
	COutMessages,
	COutCalls,
	COutSignals,
	COutBytes,
	COutAvg,
	CInMessages,
	CInCalls,
	CInMatches,
	CInBytes,
	CWakeups,
	CWkAvg,
	CPerWk,
	CPerOutMessages,
	CPerOutBytes,
	CCmdline,
};

static set<int> Active_columns;
static int Sort_column;
static bool Sort_reverse;

static const Column Columns[] = {
	{ "PID",  "%-5s",  "%-5u",  "process id" },
	{ "UNIQ", "%-7s",  "%c%-6s","unique connection name" },
	{ "NAME", "%-20s", "%-20s", "some owned name" },
	{ "MR",	  "%2s",   "%2zu",  "number of matchrules" },
	{ "O",	  "%5s",   "%5lu",  "outgoing messages" },
	{ "OC",	  "%5s",   "%5lu",  "outgoing calls" },
	{ "OS",	  "%5s",   "%5lu",  "outgoing signals" },
	{ "OB",	  "%4s",   "%4s",   "outgoing bytes" },
	{ "~OB",  "%4s",   "%4s",   "average outgoing message size" },
	{ "I",	  "%5s",   "%5lu",  "incoming messages" },
	{ "IC",	  "%5s",   "%5lu",  "incoming calls" },
	{ "IM",	  "%5s",   "%5lu",  "incoming matches" },
	{ "IB",	  "%4s",   "%4s",   "incoming bytes" },
	{ "WK",	  "%5s",   "%5lu",  "wakeups caused" },
	{ "~WK",  "%5s",   "%5lu",  "average wakeup per outgoing message" },
	{ "%WK",  "%5s",   "%5.1f", "percentage of total wakeups caused" },
	{ "%O",	  "%5s",   "%5.1f", "percentage of total messages sent" },
	{ "%OB",  "%5s",   "%5.1f", "percentage of total bytes sent" },
	{ "COMM", NULL,	   NULL,    "command line" },
};
static const int NColumns = sizeof(Columns) / sizeof(Columns[0]);

static char const Initial_help[] =
"Hit the Return key to get an overview of active clients;\n"
"type 'auto' for top-like display or 'help' for more information\n";

/* ====================
 * Forward declarations
 * ==================== */

static DBusHandlerResult
msg_handler(DBusConnection *conn, DBusMessage *msg, void *data);
static void
setup_interactive();
static void
shutdown_interactive();

/* ============
 * Program code
 * ============ */

/* ---------
 * Utilities
 * --------- */

#define GOTO_HOME "\033[1;1H"
#define GOTO_COL_1 "\033[1G"
#define CLEAR_EOL "\033[2K"
#define CLEAR_LINE "\033[K"
#define CLEAR_BOTTOM "\033[J"
#define REVERSE_VIDEO "\033[7m"
#define NORMAL_VIDEO "\033[27m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_BLUE "\033[34m"
#define COLOR_DEFAULT "\033[39m"

static int
sansi(char *s, char const *seq)
{
	if (!Interactive)
		return 0;
	else
		return sprintf(s, "%s", seq);
}

static int
ansi(char const *seq)
{
	if (!Interactive)
		return 0;
	else
		return printf("%s", seq);
}

/* Level 0 is fatal. */
static void
do_log(int level, char const *fmt, ...)
{
	if (level > Verbosity)
		return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (level == 0)
		exit(2);
}

static inline int
__attribute__((format(printf, 1, 2)))
output(char const *fmt, ...)
{
	if (Quiet)
		return 0;
	va_list ap;
	va_start(ap, fmt);
	int r = vfprintf(stdout, fmt, ap);
	va_end(ap);
	return r;
}

/* Nonblocking fgets replacement, intended usage: call refill() when stdin is
 * readable then:
 * while ((l = ngets()))
 *	process(l);
 * Returns a static buffer, or NULL if no line is found.
 */
static char Input[512];
static int Input_len;

static void
refill()
{
	int r;

	int rem = sizeof(Input) - Input_len;
retry:
	r = read(STDIN_FILENO, &Input[Input_len], rem);
	switch (r) {
	case -1:
		if (errno == EINTR || errno == EAGAIN)
			goto retry;
		log(2, "read: %m\n");
		/* fall through */
	case 0:
		Stdin_eof = true;
		break;
	default:
		Input_len += r;
		break;
	}
}

static char *
ngets()
{
	static int beg = 0;

	// adjust buffer to start at 0 in case the previous ngets call didn't
	// consume the whole thing
	if (Input_len == 0)
		return NULL;
	if (beg > 0) {
		memmove(&Input[0], &Input[beg], Input_len -= beg);
		beg = 0;
	}
	// look for \n
	int k;
	for (k = 0; k < Input_len; ++k)
		if (Input[k] == '\n')
			break;
	if (k == Input_len)
		return NULL;
	// found
	Input[k] = '\0';
	beg = k + 1;
	return Input;
}

static inline int
strcmp0(char const *a, char const *b)
{
	if (a && b) return strcmp(a, b);
	if (a) return 1;
	if (b) return -1;
	return 0;
}

/* Returns a static buffer only valid until the next call of this function. */
static char const *
cmdline_from_pid(pid_t pid)
{
	static char buf[1024];
	int n;
	int fd = -1;
	bool isok = false;

	snprintf(buf, sizeof(buf), "/proc/%u/cmdline", pid);
	if ((fd = open(buf, O_RDONLY)) < 0)
		goto out;
	n = read(fd, buf, sizeof(buf));
	if (n <= 0)
		goto out_close;
	for (int i = 0; i < n-1; ++i)
		if (!buf[i]) buf[i] = ' ';
	isok = true;
out_close:
	close(fd);
out:
	if (!isok)
		snprintf(buf, sizeof(buf), "pid-%u", pid);
	return buf;
}

static void
sighandler(int sig)
{
	switch (sig) {
	case SIGINT:   Alive = false; break;
	case SIGWINCH: Winsize.ws_col = 0; break;
	}
}

static inline void
ms_to_tv(struct timeval *tv, unsigned long ms)
{
	tv->tv_sec = ms/ 1000;
	tv->tv_usec = (ms - tv->tv_sec * 1000) * 1000;
}

static inline int
tv_to_ms(struct timeval *tv)
{
	return tv->tv_sec * 1000 + tv->tv_usec / 1000;
}

/* -------------
 * BusConnection
 * ------------- */

BusConnection::BusConnection(DBusBusType bt)
	: bustype(bt), conn(NULL), busfd(-1), ourname(NULL)
{
	if (bt == DBUS_BUS_SESSION)
		prefix = 's';
	else
		prefix = 'y';
}

/* Calls the bus driver with $call.  By default failure is fatal. */
DBusMessage *
BusConnection::call_bus(DBusMessage *call, int loglevel)
{
	DBusError err;
	DBusMessage *r;

	dbus_error_init(&err);
	r = dbus_connection_send_with_reply_and_block(conn, call,
						      1000, &err);
	dbus_message_unref(call);
	if (!r) {
		log(loglevel, "call_bus: %s\n", err.message);
		if (dbus_error_is_set(&err))
			dbus_error_free(&err);
	}
	return r;
}

/* A peer can exit faster than we do our queries (e.g. when runing under
 * valgrind), expect that. */
void
BusConnection::add_peer(char const *uniq_name, bool query_matchrules)
{
	if (uniq_name[0] != ':')
		return;

	// First get the PID.
	DBusError err;
	dbus_error_init(&err);
	DBusMessage *m = BUS_CALL_MSG("GetConnectionUnixProcessID");
	dbus_message_append_args(m, DBUS_TYPE_STRING, &uniq_name,
				 DBUS_TYPE_INVALID);
	DBusMessage *r = call_bus(m, 2);
	// Call failed.  *shrug*
	pid_t pid = 0;
	if (r) {
		if (!dbus_message_get_args(r, &err, DBUS_TYPE_UINT32, &pid,
					   DBUS_TYPE_INVALID))
			fatal(err.message);
		dbus_message_unref(r);
	}

	// Then the command line.
	Client *peer = peers[uniq_name];
	if (!peer) {
		peer = new Client(this, uniq_name);
		peers[uniq_name] = peer;
	}
	peer->bus = this;
	peer->pid = pid;
	peer->cmdline = cmdline_from_pid(pid);
	peer->unique_name = uniq_name;

	// Finally try to get the existing matchrules.
	if (!query_matchrules)
		return;

	m = BUS_CALL_MSG("GetConnectionMatchRules");
	dbus_message_append_args(m, DBUS_TYPE_STRING, &uniq_name,
				 DBUS_TYPE_INVALID);
	r = call_bus(m, 2);
	if (r) {
		char const *mr;
		if (!dbus_message_get_args(r, &err, DBUS_TYPE_STRING, &mr,
					   DBUS_TYPE_INVALID))
			fatal(err.message);
		char *rule = strdupa(mr);
		dbus_message_unref(r);
		char *end = rule;
		while (*end) {
			while (*end && *end != '\n') ++end;
			if (!*end) break;
			*end++ = '\0';
			peer->add_match(rule);
			rule = end;
		}
	}
}

void
BusConnection::remove_peer(char const *uniq_name)
{
	auto pi = peers.find(uniq_name);
	if (pi == peers.end())
		return;
	matchmaker.remove_client(pi->second);
	pi->second->croak();
}

/* Our effort to determine the commandline of the daemon.  It will fail if it
 * was started with --fork, because then it creates the listen()ing socket
 * before the (double) fork and the kernel copies the credentials to the
 * connect()ing socket from the listening socket.  This means we get the
 * grandparent's pid, which already exited.
 */
void
BusConnection::fill_daemon_info()
{
	struct ucred cred = {0};
	socklen_t ncred = sizeof(cred);
	if (getsockopt(busfd, SOL_SOCKET, SO_PEERCRED, &cred, &ncred) < 0
	    || ncred != sizeof(cred))
		return;
	if (kill(cred.pid, 0) < 0)
		// We got a ghost pid.
		cred.pid = 0;
	Client *bus = new Client(this, ":0");
	bus->bus = this;
	bus->pid = cred.pid;
	if (cred.pid > 0)
		bus->cmdline = cmdline_from_pid(cred.pid);
	else
		bus->cmdline = "dbus-daemon";
	peers[bus->unique_name] = bus;
	destinations["org.freedesktop.DBus"] = bus;
}

/* Register existing residents on the bus. */
void
BusConnection::explore()
{
	DBusError err;
	dbus_error_init(&err);

	output("Exploring existing clients on the %s bus.\n",
	       bustype == DBUS_BUS_SYSTEM ? "system" : "session");
	fill_daemon_info();

	DBusMessage *m = BUS_CALL_MSG("ListNames");
	DBusMessage *r = call_bus(m);

	char **names;
	int names_len;
	if (!dbus_message_get_args(r, &err,
		DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
		&names, &names_len,
		DBUS_TYPE_INVALID))
		fatal(err.message);
	dbus_message_unref(r);

	for (int i = 0; i < names_len; ++i) {
		char const *name = names[i];

		if (!strcmp(name, ourname))
			continue;
		if (name[0] == ':') {
			add_peer(name, true);
			continue;
		}
		// friendly name: get owner and register this alias
		m = BUS_CALL_MSG("GetNameOwner");
		dbus_message_append_args(m, DBUS_TYPE_STRING,
					 &name,
					 DBUS_TYPE_INVALID);
		r = call_bus(m);
		char *uniq_name;
		if (!dbus_message_get_args(r, &err,
					   DBUS_TYPE_STRING,
					   &uniq_name,
					   DBUS_TYPE_INVALID))
			fatal(err.message);
		dbus_message_unref(r);

		// replace daemon with :0
		if (!strcmp(uniq_name, "org.freedesktop.DBus"))
			uniq_name = (char *)":0";
		Client *peer = peers[uniq_name];
		if (!peer) {
			peer = new Client(this, uniq_name);
			peers[uniq_name] = peer;
		}
		peer->add_owned_name(name);
	}
	dbus_free_string_array(names);
}

void
BusConnection::connect()
{
	DBusError err;

	dbus_error_init(&err);
	conn = dbus_bus_get(bustype, &err);
	if (!conn) {
		char const *m = err.message;
		if (!m && bustype == DBUS_BUS_SESSION)
			m = "failed to connect to the bus, make "
				"sure you have DBUS_SESSION_BUS_ADDRESS set.";
		fatal("dbus_bus_get: %s\n", m);
	}
	ourname = dbus_bus_get_unique_name(conn);
	if (!dbus_connection_get_unix_fd(conn, &busfd))
		fatal("dbus_connection_get_unix_fd failed\n");
	if (!dbus_connection_add_filter(conn, msg_handler, this, NULL))
		fatal("dbus_connection_add_filter failed\n");

	explore();
	dbus_bus_add_match(conn, "", &err);
	if (dbus_error_is_set(&err))
		fatal("dbus_bus_add_match: %s\n", err.message);
}

void
BusConnection::shutdown()
{
	dbus_connection_remove_filter(conn, msg_handler, this);
	dbus_connection_unref(conn);
	foreach (pi, peers)
		delete pi->second;
}

/* ----------
 * Matchmaker
 * ---------- */

void
Matchmaker::add_rule(Matchrule *rule)
{
	if (!rule->interface.size() || !rule->member.size()) {
		rules2.push_back(rule);
		return;
	}
	rules.insert(make_pair(hash_rule(rule), rule));
}

void
Matchmaker::remove_rule(Matchrule *rule)
{
	if (!rule)
		return;
	if (!rule->interface.size() || !rule->member.size()) {
		rules2.remove(rule);
		return;
	}
	for (auto range = rules.equal_range(hash_rule(rule));
	     range.first != range.second; ++range.first)
	{
		if (range.first->second == rule) {
			rules.erase(range.first);
			break;
		}
	}
}

void
Matchmaker::remove_client(Client *client)
{
	for (auto ri = rules.begin(), re = rules.end(); ri != re;)
	{
		if (ri->second->owner == client)
			rules.erase(ri++);
		else
			++ri;
	}
	for (auto ri = rules2.begin(), re = rules2.end(); ri != re;)
	{
		if ((*ri)->owner == client)
			rules2.erase(ri++);
		else
			++ri;
	}
}

unsigned long
Matchmaker::hash_rule(Matchrule *rule)
{
	unsigned long h = 2166136261UL;
	if (rule->flags & Matchrule::HasInterface) {
		foreach (it, rule->interface) {
			h ^= *it;
			h *= 16777619UL;
		}
	}
	if (rule->flags & Matchrule::HasMember) {
		foreach (it, rule->member) {
			h ^= *it;
			h *= 16777619UL;
		}
	}
	return h;
}

unsigned long
Matchmaker::hash_msg(DBusMessage *msg)
{
	char const *iface = dbus_message_get_interface(msg);
	char const *member = dbus_message_get_member(msg);
	unsigned long h = 2166136261UL;
	while (iface && *iface) {
		h ^= *iface;
		h *= 16777619UL;
		++iface;
	}
	while (member && *member) {
		h ^= *member;
		h *= 16777619UL;
		++member;
	}
        return h;
}

list<Client *>
Matchmaker::matching_clients(Client *target, DBusMessage *msg) const
{
	list<Client *> ret;
	unsigned long msgh = hash_msg(msg);
	for (auto range = rules.equal_range(msgh);
	     range.first != range.second; ++range.first)
	{
		Matchrule *rule = range.first->second;
		Client *c = rule->owner;
		if (!rule->applies(msg) || target == c)
			continue;
		ret.push_back(c);
	}
	foreach (ri, rules2) {
		Matchrule *rule = *ri;
		Client *c = rule->owner;
		if (!rule->applies(msg) || target == c)
			continue;
		ret.push_back(c);
	}
	return ret;
}

void
Matchmaker::dump(FILE *stream) const
{
	fprintf(stream, "rules with interface+member (%zu)\n", rules.size());
	foreach (ri, rules) {
		fprintf(stream, "  %lu => ", ri->first);
		ri->second->dump(stream);
	}
	fprintf(stream, "rules without (%zu)\n", rules2.size());
	foreach (ri, rules2) {
		fprintf(stream, "  ");
		(*ri)->dump(stream);
	}
}

/* ---------
 * Matchrule
 * --------- */

Matchrule *Matchrule::create(char const *rule)
{
	unsigned int type = 0, flags = 0;
	char *sender, *dest, *path, *interface, *member;
	map<int, string> args;
	char const *p = rule;
	sender = dest = path = interface = member = NULL;

#define skip(cond) while (*p && cond(*p)) ++p;

	while (*p) {
		skip(isblank);
		char const *key_start = p;
		skip(isalnum);
		char const *key_end = p;
		if (key_end == key_start)
			break;
		skip(isblank);
		if (*p++ != '=')
			return NULL;
		skip(isblank);
		if (*p++ != '\'')
			return NULL;
		char const *val_start = p;
		// XXX we don't care about escaping
		while (*p && *p != '\'') ++p;
		if (*p != '\'')
			return NULL;
		char const *val_end = p++;
		string key(key_start, key_end - key_start);
		char *val = strndupa(val_start, val_end - val_start);
		//debug("key=[%s] val=[%s]\n", key.c_str(), val);
		if (key == "type") {
			if (!strcmp(val, "signal"))
				type = DBUS_MESSAGE_TYPE_SIGNAL;
			else if (!strcmp(val, "method_call"))
				type = DBUS_MESSAGE_TYPE_METHOD_CALL;
			else if (!strcmp(val, "method_return"))
				type = DBUS_MESSAGE_TYPE_METHOD_RETURN;
			else if (!strcmp(val, "error"))
				type = DBUS_MESSAGE_TYPE_ERROR;
			else
				return NULL;
			flags |= HasType;
		} else if (key == "sender") {
			sender = val;
			flags |= HasSender;
		} else if (key == "destination") {
			dest = val;
			flags |= HasDest;
		} else if (key == "path") {
			path = val;
			flags |= HasPath;
		} else if (key == "interface") {
			interface = val;
			flags |= HasInterface;
		} else if (key == "member") {
			member = val;
			flags |= HasMember;
		} else if (!strncmp(key_start, "arg", 3)) {
			// XXX we don't care about argXpath
			key_start += 3;
			char *endp;
			unsigned long argnum = strtoul(key_start, &endp, 10);
			if (key_start == endp || argnum > 63)
				return NULL;
			args[argnum] = val;
			flags |= HasArgs;
		} else
			return NULL;
		skip(isblank);
		if (*p++ != ',')
			break;
	}
#undef skip
	Matchrule *mr = new Matchrule();
	mr->flags = flags;
	if (flags & HasType)      mr->type = type;
	if (flags & HasSender)    mr->sender = sender;
	if (flags & HasDest)      mr->dest = dest;
	if (flags & HasPath)      mr->path = path;
	if (flags & HasInterface) mr->interface = interface;
	if (flags & HasMember)    mr->member = member;
	if (flags & HasArgs)      mr->args = args;
	return mr;
}

bool
Matchrule::applies(DBusMessage *msg) const
{
	if (flags & HasType && type != dbus_message_get_type(msg))
		return false;
	if (flags & HasSender &&
	    strcmp0(sender.c_str(), dbus_message_get_sender(msg)))
		return false;
	if (flags & HasDest &&
	    strcmp0(dest.c_str(), dbus_message_get_destination(msg)))
		return false;
	if (flags & HasPath &&
	    strcmp0(path.c_str(), dbus_message_get_path(msg)))
		return false;
	if (flags & HasInterface &&
	    strcmp0(interface.c_str(), dbus_message_get_interface(msg)))
		return false;
	if (flags & HasMember &&
	    strcmp0(member.c_str(), dbus_message_get_path(msg)))
		return false;
	if (flags & HasArgs) {
		int maxarg = args.rbegin()->first;
		DBusMessageIter iter;
		if (!dbus_message_iter_init(msg, &iter))
			return false;
		auto ai = args.begin();
		int i;
		for (i = 0; i <= maxarg; ++i) {
			if (dbus_message_iter_get_arg_type(&iter) ==
			    DBUS_TYPE_INVALID)
				break;
			if (ai->first == i) {
				// we have an expectation for this arg
				if (dbus_message_iter_get_arg_type(&iter) !=
				    DBUS_TYPE_STRING)
					return false;
				char const *arg;
				dbus_message_iter_get_basic(&iter, &arg);
				if (!arg)
					return false;
				if (strcmp(arg, ai->second.c_str()))
					return false;
				++ai;
			}
			dbus_message_iter_next(&iter);
		}
		// we didn't match all expectations
		if (i <= maxarg || ai != args.end())
			return false;
	}
	return true;
}

bool
rule_equal(Matchrule *const &a, Matchrule *const &b)
{
	return  a->flags == b->flags &&
		a->type == b->type &&
		a->sender == b->sender &&
		a->dest == b->dest &&
		a->path == b->path &&
		a->interface == b->interface &&
		a->member == b->member &&
		a->args == b->args;
}

void
Matchrule::dump(FILE *stream) const
{
	static char const *ruletype[] = {
		"invalid", "method_call", "method_return", "error", "signal"
	};
	fprintf(stream, "Rule");
	if (flags & HasType)
		fprintf(stream, " type='%s'", ruletype[type]);
	if (flags & HasSender)
		fprintf(stream, " sender='%s'", sender.c_str());
	if (flags & HasDest)
		fprintf(stream, " destination='%s'", dest.c_str());
	if (flags & HasPath)
		fprintf(stream, " path='%s'", path.c_str());
	if (flags & HasInterface)
		fprintf(stream, " interface='%s'", interface.c_str());
	if (flags & HasMember)
		fprintf(stream, " member='%s'", member.c_str());
	foreach (ai, args)
		fprintf(stream, " arg%d='%s'",
			ai->first, ai->second.c_str());
	fputc('\n', stream);
}

/* ------
 * Client
 * ------ */

bool operator<(Client::DetailKey const &a, Client::DetailKey const &b)
{
	if (a.peer < b.peer)
		return true;
	if (b.peer < a.peer)
		return false;
	if (a.msg < b.msg)
		return true;
	if (b.msg < a.msg)
		return false;
	return false;
}

Client::Client(BusConnection *bus, char const *uniq) :
	pid(0), bus(bus), unique_name(uniq), exited(false), last_activity(0),
	current({0}), total({0})
{
	bus->destinations[unique_name] = this;
}

Client::~Client()
{
	Selection.erase(this);
	bus->matchmaker.remove_client(this);
	bus->destinations.erase(unique_name);
	foreach (ri, match_rules)
		delete *ri;
}

void
Client::add_match(char const *rule_str)
{
	Matchrule *mr = Matchrule::create(rule_str);
	if (!mr) return;
	mr->owner = this;
	match_rules.push_back(mr);
	bus->matchmaker.add_rule(mr);
}

void
Client::remove_match(char const *rule_str)
{
	Matchrule *tmr = Matchrule::create(rule_str);
	if (!tmr) return;
	// Remove the last from the list (like dbus does).
	Matchrule *mr = NULL;
	for (auto it = match_rules.rbegin(),
		     ie = match_rules.rend();
	     it != ie; ++it)
	{
		if (rule_equal(*it, tmr)) {
			mr = *it;
			match_rules.erase(--it.base());
			break;
		}
	}
	bus->matchmaker.remove_rule(mr);
	delete mr;
	delete tmr;
}

void
Client::add_owned_name(char const *name)
{
	owned_names.insert(name);
	bus->destinations[name] = this;
	ever_owned_names.insert(name);
}

void
Client::remove_owned_name(char const *name)
{
	owned_names.erase(name);
	bus->destinations.erase(name);
}

void
Client::croak()
{
	exited = true;
	bus->destinations.erase(unique_name);
	foreach (ni, owned_names)
		bus->destinations.erase(*ni);
}

void
Client::reset_counters(bool all)
{
	current.out_messages = 0;
	current.out_calls = 0;
	current.out_signals = 0;
	current.out_bytes = 0;
	current.in_messages = 0;
	current.in_calls = 0;
	current.in_matches = 0;
	current.in_bytes = 0;
	current.wakeups = 0;
	Details().swap(current.sent);
	Details().swap(current.received);
	if (all) {
		total.out_messages = 0;
		total.out_calls = 0;
		total.out_signals = 0;
		total.out_bytes = 0;
		total.in_messages = 0;
		total.in_calls = 0;
		total.in_matches = 0;
		total.in_bytes = 0;
		total.wakeups = 0;
		Details().swap(total.sent);
		Details().swap(total.received);
	}
}

void
Client::dump(FILE *stream) const
{
	fprintf(stream,
		"Client(%p) unique_name: %s pid: %u%s\n"
		"  commandline: %s\n"
		"  owned names (%zu):\n",
		this, unique_name.c_str(), pid,
		exited ? " (exited)" : "",
		cmdline.c_str(), owned_names.size());
	foreach (ni, owned_names)
		fprintf(stream, "     %s\n", ni->c_str());
	foreach (ni, ever_owned_names)
		fprintf(stream, "    *%s\n", ni->c_str());
	fprintf(stream, "  matchrules (%zu):\n",
		match_rules.size());
	foreach (ri, match_rules) {
		fprintf(stream, "    ");
		(*ri)->dump(stream);
	}
	fprintf(stream,
		"  COUNTERS         current     total\n"
		"  out_messages     %7lu   %7lu\n"
		"  out_calls        %7lu   %7lu\n"
		"  out_signals      %7lu   %7lu\n"
		"  out_bytes        %7lu   %7lu\n"
		"  in_messages      %7lu   %7lu\n"
		"  in_calls         %7lu   %7lu\n"
		"  in_matches       %7lu   %7lu\n"
		"  in_bytes         %7lu   %7lu\n"
		"  wakeups caused   %7lu   %7lu\n",
		current.out_messages, total.out_messages,
		current.out_calls, total.out_calls,
		current.out_signals, total.out_signals,
		current.out_bytes, total.out_bytes,
		current.in_messages, total.in_messages,
		current.in_calls, total.in_calls,
		current.in_matches, total.in_matches,
		current.in_bytes, total.in_bytes,
		current.wakeups, total.wakeups);
/*
  MESSAGE                                     COUNT  BYTES
  X 1234567890123456789012345678901234567890  99999   999m

  SENDER   MESSAGE                                     COUNT  BYTES
  :9.9999  X 1234567890123456789012345678901234567890  99999   999m
*/
	if (current.sent.size()) {
		fprintf(stream, "  OUTBOUND\n");
		fprintf(stream, "    %-6s  %-50s  %5s  %5s\n",
			"DEST", "MESSAGE", "COUNT", "BYTES");
		foreach (si, current.sent)
			fprintf(stream, "    %-6s  %-50s  %5lu  %5lu\n",
				si->first.peer.c_str(),
				si->first.msg.c_str(),
				si->second.count, si->second.bytes);
	}
	if (current.received.size()) {
		fprintf(stream, "  INBOUND\n");
		fprintf(stream, "    %-6s  %-50s  %5s  %5s\n",
			"SENDER", "MESSAGE", "COUNT", "BYTES");
		foreach (si, current.received)
			fprintf(stream, "    %-6s  %-50s  %5lu  %5lu\n",
				si->first.peer.c_str(),
				si->first.msg.c_str(),
				si->second.count, si->second.bytes);
	}
}

bool
is_selected(Client const *client)
{
	return Selection.find(const_cast<Client *>(client))
		!= Selection.end();
}

char const *
Client::displayname() const
{
	char const *name = "-";
	if (!owned_names.size())
		return name;
	string const &fn(*owned_names.begin());
	name = fn.c_str();
	if (Interactive) {
		size_t l = fn.size();
		if (l > 20)
			name += l - 20;
	}
	return name;
}

void
Client::refresh_cmdline() const
{
	/* HACK: requery command line if the current one is booster or
	 * applauncher. */
	if (exited ||
	    !(strstr(cmdline.c_str(), "applauncherd.bin") ||
	      strstr(cmdline.c_str(), "booster")))
		return;
	cmdline = cmdline_from_pid(pid);
}

/* ------------
 * Fancy output
 * ------------ */

/* In non-interactive mode nothing is limited or ellipsized, and byte
 * quantities are unscaled. */

struct Comparator {
	bool operator()(Client const *a, Client const *b) const;

	int column;
	bool reverse;
	bool show_totals;
};

bool
Comparator::operator()(Client const *a, Client const *b) const
{
	if (reverse)
		swap(a, b);
	// We can shortcut if we are sorting dead clients to the end and
	// only one of {a,b} has exited.
	if (Gone_last && a->exited ^ b->exited)
		return a->exited;

	Client::Counters const &ac = show_totals ? a->total : a->current;
	Client::Counters const &bc = show_totals ? b->total : b->current;

	switch (column) {
	case CPid:
		return a->pid < b->pid;
	case CUniqueName:
		return a->unique_name < b->unique_name;
	case CName:
		return strcmp(a->displayname(), b->displayname()) < 0;
	case CNrMatchrules:
		return a->match_rules.size() < b->match_rules.size();
	case COutMessages:
		return ac.out_messages < bc.out_messages;
	case COutCalls:
		return ac.out_calls < bc.out_calls;
	case COutSignals:
		return ac.out_signals < bc.out_signals;
	case COutBytes:
		return ac.out_bytes < bc.out_bytes;
	case COutAvg: {
		// hm, this cannot be div0, that would mean no messages
		// but some bytes
		unsigned long av = ac.out_messages ?
			ac.out_bytes / ac.out_messages : 0;
		unsigned long bv = bc.out_messages ?
			bc.out_bytes / bc.out_messages : 0;
		return av < bv;
	}
	case CInMessages:
		return ac.in_messages < bc.in_messages;
	case CInCalls:
		return ac.in_calls < bc.in_calls;
	case CInMatches:
		return ac.in_matches < bc.in_matches;
	case CInBytes:
		return ac.in_bytes < bc.in_bytes;
	case CWakeups:
		return ac.wakeups < bc.wakeups;
	case CWkAvg: {
		unsigned long av = ac.out_messages ?
			ac.wakeups / ac.out_messages : 0;
		unsigned long bv = bc.out_messages ?
			bc.wakeups / bc.out_messages : 0;
		return av < bv;
	}
	case CPerWk: {
		float av = Stats.total_wakeups ?
			100.0f * ac.wakeups / Stats.total_wakeups : 0;
		float bv = Stats.total_wakeups ?
			100.0f * bc.wakeups / Stats.total_wakeups : 0;
		return av < bv;
	}
	case CPerOutMessages: {
		float av = Stats.total_messages ?
			100.0f * ac.out_messages / Stats.total_messages : 0;
		float bv = Stats.total_messages ?
			100.0f * bc.out_messages / Stats.total_messages : 0;
		return av < bv;
	}
	case CPerOutBytes: {
		float av = Stats.total_bytes ?
			100.0f * ac.out_bytes / Stats.total_bytes : 0;
		float bv = Stats.total_bytes ?
			100.0f * bc.out_bytes / Stats.total_bytes : 0;
		return av < bv;
	}
	case CCmdline:
		return a->cmdline < b->cmdline;
	}
	/* NOTREACHED */
	abort();
	return false;
}

static int
format_bytes(unsigned long v)
{
	if (!Interactive)
		return printf("%lu", v);
	if (v > 1000000)
		return printf("%3lum", v / 1000000);
	if (v > 1000)
		return printf("%3luk", v / 1000);
	return printf("%4lu", v);
}

static int
format_column(ColumnId column, Client const &cli,
	      bool show_totals, int printed)
{
	Client::Counters const &c = show_totals ? cli.total : cli.current;
	char const *fmt = Columns[column].fmt;

	switch (column) {
	case CPid:
		return printf(fmt, cli.pid);
	case CUniqueName:
		return printf(fmt, cli.bus->prefix, cli.unique_name.c_str());
	case CName:
		return printf(fmt, cli.displayname());
	case CNrMatchrules:
		return printf(fmt, cli.match_rules.size());
	case COutMessages:
		return printf(fmt, c.out_messages);
	case COutCalls:
		return printf(fmt, c.out_calls);
	case COutSignals:
		return printf(fmt, c.out_signals);
	case COutBytes:
		return format_bytes(c.out_bytes);
	case COutAvg: {
		unsigned long v = c.out_messages ?
			c.out_bytes / c.out_messages : 0;
		return format_bytes(v);
	}
	case CInMessages:
		return printf(fmt, c.in_messages);
	case CInCalls:
		return printf(fmt, c.in_calls);
	case CInMatches:
		return printf(fmt, c.in_matches);
	case CInBytes:
		return format_bytes(c.in_bytes);
	case CWakeups:
		return printf(fmt, c.wakeups);
	case CWkAvg: {
		unsigned long v = c.out_messages ?
			c.wakeups / c.out_messages : 0;
		return printf(fmt, v);
	}
	case CPerWk: {
		float v = Stats.total_wakeups ?
			100.0f * c.wakeups / Stats.total_wakeups : 0;
		return printf(fmt, v);
	}
	case CPerOutMessages: {
		float v = Stats.total_messages ?
			100.0f * c.out_messages / Stats.total_messages : 0;
		return printf(fmt, v);
	}
	case CPerOutBytes: {
		float v = Stats.total_bytes ?
			100.0f * c.out_bytes / Stats.total_bytes : 0;
		return printf(fmt, v);
	}
	case CCmdline:
		cli.refresh_cmdline();
		if (Interactive)
			return printf("%-.*s", Winsize.ws_col - printed,
				      cli.cmdline.c_str());
		else
			return printf("%s", cli.cmdline.c_str());
	}
	/* NOTREACHED */
	abort();
	return 0;
}

static bool
should_show_client(Client const *c)
{
	if (Use_view == ViewAll)
		return true;
	if (Use_view == ViewSelection)
		return is_selected(c);
	if (Use_view == ViewActive)
		return c->last_activity > Last_reset;
	return false;
}

static void
get_clients_to_show(vector<Client *> &clients)
{
	size_t ps = 0;
	foreach (bi, Buses)
		ps += (*bi)->peers.size();

	clients.reserve(ps);
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers) {
			Client *c = pi->second;
			if (should_show_client(c))
				clients.push_back(c);
		}
	}

	Comparator cmp;
	cmp.column = Sort_column;
	cmp.reverse = Sort_reverse;
	cmp.show_totals = Show_totals;
	sort(clients.begin(), clients.end(), cmp);
}

static void
cmd_overview(char const *args)
{
	if (Interactive && Winsize.ws_col == 0)
		ioctl(0, TIOCGWINSZ, &Winsize);

	static char header[512];
	char *hdr = header;

	// header
	hdr += sansi(hdr, REVERSE_VIDEO);
	int chars = 0;
	foreach (ci, Active_columns) {
		int i = *ci;
		Column const &col = Columns[i];
		*hdr++ = ' ';
		++chars;
		if (i == Sort_column)
			hdr += sansi(hdr, COLOR_GREEN);
		// last column has to be cmdline and it's special:
		// fills the rest of the line
		if (i == NColumns - 1) {
			if (Interactive)
				hdr += sprintf(hdr, "%-*s",
					       Winsize.ws_col - chars,
					       col.header);
			else
				hdr += sprintf(hdr, "%s", col.header);
		} else {
			int c = sprintf(hdr, col.headerfmt, col.header);
			chars += c;
			hdr += c;
		}
		if (i == Sort_column)
			hdr += sansi(hdr, COLOR_DEFAULT);
	}
	hdr += sansi(hdr, NORMAL_VIDEO);
	*hdr++ = '\n';
	*hdr++ = '\0';
	printf("%s", header);

	vector<Client *> clients;
	get_clients_to_show(clients);

	// 1 for header, and 1 for help.
	int shown_rows = 2;
	// Don't display more than a screenful in top-mode.
	if (Autorefresh && Interactive) {
		int over = clients.size() - (Winsize.ws_row - shown_rows - 1);
		if (over > 0)
			clients.erase(clients.end() - over, clients.end());
	}
	// Now print them.
	foreach (ci, clients) {
		Client const &c = **ci;
		int chars = 0;
		chars += printf("%c", c.exited ? '*' : ' ');
		foreach (ci, Active_columns) {
			int i = *ci;
			if (i > 0) {
				putchar(' ');
				++chars;
			}
			chars += format_column(static_cast<ColumnId>(i),
					       c, Show_totals, chars);
		}
		ansi(CLEAR_LINE);
		putchar('\n');
		++shown_rows;
	}
	// Repeat header if we printed more than a screenful.
	if (!Autorefresh && Interactive && shown_rows > Winsize.ws_row)
		printf("%s", header);
}

enum PrintWhat {
	DBrief    = 1 << 0,
	DNames    = 1 << 1,
	DCounters = 1 << 2,
	DMessages = 1 << 3,
	DRules    = 1 << 4,
	DAll      = DBrief | DNames | DCounters | DMessages | DRules,
};

static void
print_details_of(Client const *cli, int what)
{
	auto counters = Show_totals ? cli->total : cli->current;

	cli->refresh_cmdline();
	if (what & DBrief)
		printf("CLIENT %c%-6s %6u %c %s\n",
		       cli->bus->prefix, cli->unique_name.c_str(),
		       cli->pid, cli->exited ? 'X' : 'R',
		       cli->cmdline.c_str());

	if (what & DNames) {
		printf("OWNED NAMES (%zu)\n", cli->owned_names.size());
		foreach (ni, cli->owned_names)
			printf("   %s\n", ni->c_str());
		foreach (ni, cli->ever_owned_names)
			printf("  *%s\n", ni->c_str());
	}

	if (what & DCounters) {
		printf("COUNTERS           current     total\n"
		       "  out_messages     %7lu   %7lu\n"
		       "  out_calls        %7lu   %7lu\n"
		       "  out_signals      %7lu   %7lu\n"
		       "  out_bytes        %7lu   %7lu\n"
		       "  in_messages      %7lu   %7lu\n"
		       "  in_calls         %7lu   %7lu\n"
		       "  in_matches       %7lu   %7lu\n"
		       "  in_bytes         %7lu   %7lu\n"
		       "  wakeups caused   %7lu   %7lu\n",
		       cli->current.out_messages, cli->total.out_messages,
		       cli->current.out_calls, cli->total.out_calls,
		       cli->current.out_signals, cli->total.out_signals,
		       cli->current.out_bytes, cli->total.out_bytes,
		       cli->current.in_messages, cli->total.in_messages,
		       cli->current.in_calls, cli->total.in_calls,
		       cli->current.in_matches, cli->total.in_matches,
		       cli->current.in_bytes, cli->total.in_bytes,
		       cli->current.wakeups, cli->total.wakeups);
	}

	if (what & DRules) {
		printf("MATCHRULES (%zu)\n", cli->match_rules.size());
		foreach (ri, cli->match_rules) {
			printf("  ");
			(*ri)->dump(stdout);
		}
	}

	if (what & DMessages) {
		unsigned longest = 0;
		foreach (si, counters.sent)
			if (si->first.msg.size() > longest)
				longest = si->first.msg.size();
		foreach (si, counters.received)
			if (si->first.msg.size() > longest)
				longest = si->first.msg.size();

		typedef multimap<unsigned long, Client::Details::iterator> SM;

		SM sm;
		foreach (si, counters.sent)
			sm.insert(make_pair(si->second.count, si));
		printf("PER-MESSAGE COUNTERS\n");
		foreach (smi, sm) {
			auto si = smi->second;
			printf("  out  %-*s  %5lu  ",
			       longest, si->first.msg.c_str(),
			       si->second.count);
			format_bytes(si->second.bytes);
			printf("  %-7s\n", si->first.peer.c_str());
		}
		SM().swap(sm);
		foreach (si, counters.received)
			sm.insert(make_pair(si->second.count, si));
		foreach (smi, sm) {
			auto si = smi->second;
			printf("  in   %-*s  %5lu  ",
			       longest, si->first.msg.c_str(),
			       si->second.count);
			format_bytes(si->second.bytes);
			printf("  %-7s\n", si->first.peer.c_str());
		}
	}

}

static void
cmd_details(char const *args)
{
	int what = 0;
	char w[64] = {0};
	int n;
	while (sscanf(args, " %63s%n", w, &n) > 0) {
		size_t l = strlen(w);
		if (!strncasecmp("all", w, l)) {
			what = DAll;
			break;
		} else if (!strncasecmp("brief", w, l))
			what |= DBrief;
		else if (!strncasecmp("names", w, l))
			what |= DNames;
		else if (!strncasecmp("counters", w, l))
			what |= DCounters;
		else if (!strncasecmp("messages", w, l))
			what |= DMessages;
		else if (!strncasecmp("rules", w, l))
			what |= DRules;
		args += n;
	}
	if (!what)
		what = DMessages;
	what |= DBrief;

	if (Selection.size() || Use_view == ViewSelection) {
		foreach (si, Selection)
			print_details_of(*si, what);
	} else {
		foreach (bi, Buses) {
			foreach (pi, (*bi)->peers) {
				Client const *c = pi->second;
				if (Use_view == ViewActive &&
				    c->last_activity <= Last_reset)
					continue;
				print_details_of(c, what);
			}
		}
	}
}

static void
reset_clients(char const *args)
{
	bool all = !strcmp(args, "all");
	foreach (bi, Buses) {
		auto &peers = (*bi)->peers;
		// Kill dead peers and reset counters for the living.
		for (auto pi = peers.begin(), pe = peers.end();
		     pi != pe; )
		{
			Client *c = pi->second;
			if (c->exited) {
				peers.erase(pi++);
				delete c;
			} else {
				c->reset_counters(all);
				++pi;
			}
		}
		// TODO shrink peers?
	}
	// Remember last reset.
	Last_reset = Last_event;
	output("%s counters reset.\n",
	       all ? "All" : "Current");
}


/* ---------------------
 * D-Bus related helpers
 * --------------------- */

static char
msgtype(DBusMessage *msg)
{
	static char const types[] = "xCRES";
	unsigned int type = dbus_message_get_type(msg);
	if (type < sizeof(types))
		return types[type];
	return '?';
}

static string
msgkind(DBusMessage *msg)
{
	string s;
	s.reserve(32);
	s += msgtype(msg);
	if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR) {
		s += ' ';
		s += dbus_message_get_error_name(msg);
	} else {
		if (dbus_message_get_interface(msg)) {
			s += ' ';
			s += dbus_message_get_interface(msg);
		}
		if (dbus_message_get_member(msg)) {
			s += '.';
			s += dbus_message_get_member(msg);
		}
	}
	return s;
}

static void
handle_nameownerchanged(BusConnection *bus, char const *name,
			char const *oldname, char const *newname)
{
	bool uniq = name[0] == ':';
	//debug("nameownerchanged: %s %s %s\n", name, oldname, newname);
	if (newname[0] && oldname[0]) {
		// a name has changed owners
		if (uniq) {
			log(2, "oops, an unique name changing owners?\n");
			return;
		}
		bus->peers[oldname]->remove_owned_name(name);
		bus->peers[newname]->add_owned_name(name);
	} else if (newname[0]) {
		// appeared / name acquired
		if (uniq)
			bus->add_peer(newname, false);
		else
			bus->peers[newname]->add_owned_name(name);
	} else if (oldname[0]) {
		// disappeared / name lost
		if (uniq)
			bus->remove_peer(oldname);
		else
			bus->peers[oldname]->remove_owned_name(name);
	}
}

static void
account_message(BusConnection *bus, DBusMessage *msg,
		char const *sender, char const *dest,
		struct timeval *t)
{
	int type = dbus_message_get_type(msg);

	if (Ignore_replies && type == DBUS_MESSAGE_TYPE_METHOD_RETURN)
		return;

	++Last_event;

	// Hello Ladies!  Look at your code...
	Client *s = bus->peers[sender];
	bool had_selected = false;

	if (Monitor)
		had_selected |= is_selected(s);

	// The sender might be gone...
	if (!s) {
		log(2, "sender is gone, i think it shouldn't happen now\n");
		return;
	}

	// Find out the length of the message.
	int msg_len = 0;
	char *tmp;
	dbus_message_marshal(msg, &tmp, &msg_len);
	free(tmp);

	// 1. at sender

	string msgk(msgkind(msg));

	// Prepend bus prefix if it's an unique name.
	// XXX slight inconsistency, how do you recognize friendly names
	// different buses?
	string k(dest ? dest : "-");
	if (k[0] == ':')
		k = bus->prefix + k;
	auto sk = Client::DetailKey(k, msgk);
	k = bus->prefix;
	k += sender;
	auto rk = Client::DetailKey(k, msgk);

	s->current.out_bytes += msg_len;
	s->total.out_bytes += msg_len;
	s->current.sent[sk].count += 1;
	s->total.sent[sk].count += 1;
	s->current.sent[sk].bytes += msg_len;
	s->total.sent[sk].bytes += msg_len;
	s->current.out_messages++;
	s->total.out_messages++;
	if (type != DBUS_MESSAGE_TYPE_SIGNAL) {
		s->current.out_calls++;
		s->total.out_calls++;
	} else {
		s->current.out_signals++;
		s->total.out_signals++;
	}
	s->last_activity = Last_event;

	// ... now back to mine!  Now back at your code!
	// 2. at destinations
	unsigned int woken = 0;

	// Check direct destination.
	Client *target = NULL;
	if (dest && (target = bus->destinations[dest])) {
		target->current.in_messages++;
		target->total.in_messages++;
		target->current.in_calls++;
		target->total.in_calls++;
		target->current.in_bytes += msg_len;
		target->total.in_bytes += msg_len;
		target->current.received[rk].count++;
		target->total.received[rk].count++;
		target->current.received[rk].bytes += msg_len;
		target->total.received[rk].bytes += msg_len;
		target->last_activity = Last_event;
		if (Monitor)
			had_selected |= is_selected(target);
	}

	// Look up matchrule based on some hash of the message.
	list<Client *> const &matches =
		bus->matchmaker.matching_clients(target, msg);
	foreach (ci, matches) {
		Client *p = *ci;
		p->current.in_matches++;
		p->total.in_matches++;
		p->current.in_messages++;
		p->total.in_messages++;
		++woken;
		p->current.in_bytes += msg_len;
		p->total.in_bytes += msg_len;
		p->current.received[rk].count += 1;
		p->total.received[rk].count += 1;
		p->current.received[rk].bytes += msg_len;
		p->total.received[rk].bytes += msg_len;
		p->last_activity = Last_event;
		if (Monitor)
			had_selected |= is_selected(p);
	}

	// ... back to me again!  Does your code smell like mine?
	// 3. at sender after we know the destinations
	s->current.wakeups += woken;
	s->total.wakeups += woken;

	// 4. totals
	Stats.total_messages++;
	Stats.total_bytes += msg_len;
	Stats.total_wakeups += woken;

	// Selective dbus-monitor: if we have a selection and the message
	// `touched' one of them, display it.  If we don't have, display it
	// unconditionally.
	if (Monitor && (had_selected || !Selection.size())) {
		ansi(GOTO_COL_1 CLEAR_EOL);
		unsigned int serial;
		if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN)
			serial = dbus_message_get_reply_serial(msg);
		else
			serial = dbus_message_get_serial(msg);
		printf("%lu.%03lu %5u %5u %c %c%-6s %s ",
		       t->tv_sec, t->tv_usec / 1000, msg_len, serial,
		       msgtype(msg), bus->prefix, sender, dest ? dest : "-");

		switch (type) {
		case DBUS_MESSAGE_TYPE_ERROR:
			printf(" %s\n", dbus_message_get_error_name(msg));
			break;
		case DBUS_MESSAGE_TYPE_SIGNAL:
		case DBUS_MESSAGE_TYPE_METHOD_CALL:
			printf(" %s %s.%s\n",
			       dbus_message_get_path(msg),
			       dbus_message_get_interface(msg),
			       dbus_message_get_member(msg));
			break;
		case DBUS_MESSAGE_TYPE_METHOD_RETURN:
			putchar('\n');
			break;
		default: break;
		}
		if (Interactive)
			rl_forced_update_display();
	}
}

static DBusHandlerResult
msg_handler(DBusConnection *conn, DBusMessage *msg, void *data)
{
	BusConnection *bus = static_cast<BusConnection *>(data);

	if (dbus_message_is_signal(msg, DBUS_INTERFACE_LOCAL, "Disconnected"))
	{
		Alive = false;
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	struct timeval t;
	gettimeofday(&t, NULL);

	char const *sender = dbus_message_get_sender(msg);
	char const *dest = dbus_message_get_destination(msg);

	// Ignore messages from or to us.
	if ((sender && !strcmp(sender, bus->ourname)) ||
	    (dest && !strcmp(dest, bus->ourname)))
		return DBUS_HANDLER_RESULT_HANDLED;

	// Replace the daemon with :0 for kicks.
	if (!strcmp(sender, "org.freedesktop.DBus"))
		sender = ":0";

	account_message(bus, msg, sender, dest, &t);

	if (dbus_message_is_signal(msg, DBUS_IF, "NameOwnerChanged")) {
		char const *name, *oldname, *newname;

		if (!dbus_message_get_args(msg, NULL,
					   DBUS_TYPE_STRING, &name,
					   DBUS_TYPE_STRING, &oldname,
					   DBUS_TYPE_STRING, &newname,
					   DBUS_TYPE_INVALID))
			return DBUS_HANDLER_RESULT_HANDLED;

		handle_nameownerchanged(bus, name, oldname, newname);
	}
	if (dbus_message_is_method_call(msg, DBUS_IF, "AddMatch")) {
		char const *rule;
		if (!dbus_message_get_args(msg, NULL,
					   DBUS_TYPE_STRING, &rule,
					   DBUS_TYPE_INVALID))
			return DBUS_HANDLER_RESULT_HANDLED;
		bus->peers[sender]->add_match(rule);
	}
	if (dbus_message_is_method_call(msg, DBUS_IF, "RemoveMatch")) {
		char const *rule;
		if (!dbus_message_get_args(msg, NULL,
					   DBUS_TYPE_STRING, &rule,
					   DBUS_TYPE_INVALID))
			return DBUS_HANDLER_RESULT_HANDLED;
		bus->peers[sender]->remove_match(rule);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void
setup_dbus()
{
	foreach (bi, Buses)
		(*bi)->connect();
}

static void
shutdown_dbus()
{
	foreach (bi, Buses) {
		(*bi)->shutdown();
		delete *bi;
	}
}

/* -----------
 * UI commands
 * ----------- */

static char *
complete_command(char const *text, int state)
{
	static map<string, Command>::const_iterator cmd;
	static int len = 0;
	if (!state) {
		len = strlen(text);
		cmd = Commands.begin();
	}
	while (cmd != Commands.end()) {
		if (!strncmp(cmd->first.c_str(), text, len))
			break;
		++cmd;
	}
	if (cmd == Commands.end())
		return NULL;
	return strdup(cmd++->first.c_str());
}

Command::Command(char const *name, char const *args,
		 Command_fn fn, char const *desc, char const *help)
: name(name), args(args), func(fn), desc(desc), help(help)
{
}

void
Command::print_brief() const
{
	printf("%-15s %-20s  %s\n",
	       name, args ? args : "",
	       desc);
}

void
Command::print_help() const
{
	print_brief();
	if (help)
		printf("\n%s\n", help);
}

static bool
bool_fromarg(char const *args, bool &flag)
{
	if (!*args)
		flag = !flag;
	else if (!strcmp(args, "1") || !strcmp(args, "on") ||
		 !strcmp(args, "yes") || !strcmp(args, "true"))
		flag = true;
	else if (!strcmp(args, "0") || !strcmp(args, "off") ||
		 !strcmp(args, "no") || !strcmp(args, "false"))
		flag = false;
	else {
		printf("Boolean argument expected.\n");
		return false;
	}
	return true;
}

static inline void
add_sel(Client *client)
{
	Selection.insert(client);
}

static void
select_all()
{
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers)
			add_sel(pi->second);
	}
}
static void
select_active()
{
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers)
			if (pi->second->last_activity > Last_reset)
				add_sel(pi->second);
	}
}
static void
select_by_unique_name(char const *uniq)
{
	foreach (bi, Buses) {
		if (uniq[0] != (*bi)->prefix)
			continue;
		uniq++;
		foreach (pi, (*bi)->peers)
			if (pi->second->unique_name == uniq)
				add_sel(pi->second);
		break;
	}
}
/* true if A 'covers' B, meaning the present fields in A are equal to
 * corresponding fields in B */
static inline bool
rule_covers(Matchrule *const a, Matchrule *const b)
{
	// B needs to be a superset of A
	if ((a->flags & b->flags) != a->flags)
		return false;
	if (a->flags & Matchrule::HasType && a->type != b->type)
		return false;
	if (a->flags & Matchrule::HasSender && a->sender != b->sender)
		return false;
	if (a->flags & Matchrule::HasDest && a->dest != b->dest)
		return false;
	if (a->flags & Matchrule::HasPath && a->path != b->path)
		return false;
	if (a->flags & Matchrule::HasInterface && a->interface != b->interface)
		return false;
	if (a->flags & Matchrule::HasMember && a->member != b->member)
		return false;
	if (a->flags & Matchrule::HasArgs) {
		// all argXs present in A have to be equal to B's
		foreach (ai, a->args)
			if (b->args[ai->first] != ai->second)
				return false;
	}
	return true;
}
static void
select_by_matchrule(char const *rule)
{
	Matchrule *r = Matchrule::create(rule);
	if (!r) return;
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers)
			foreach (ri, pi->second->match_rules)
				if (rule_covers(r, *ri))
					add_sel(pi->second);
	}
	delete r;
}
static void
select_by_pid(pid_t pid)
{
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers)
			if (pi->second->pid == pid)
				add_sel(pi->second);
	}
}
static void
select_by_cmdline(char const *str)
{
	string ss(str);
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers)
			if (pi->second->cmdline.find(ss) != string::npos)
				add_sel(pi->second);
	}
}
static void
select_by_owned_name(char const *str)
{
	string ss(str);
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers)
			foreach (ni, pi->second->owned_names)
				if (ni->find(ss))
					add_sel(pi->second);
	}
}

static void
select_by_msg(char const *m)
{
	bool sent = m[0] == '>';
	++m;
	foreach (bi, Buses) {
		foreach (pi, (*bi)->peers) {
			Client *cli = pi->second;
			auto ctr = Show_totals ? cli->current : cli->total;
			Client::Details const &det = sent ?
				ctr.sent : ctr.received;
			foreach (mi, det) {
				string const &msgk = mi->first.msg;
				if (strstr(msgk.c_str(), m)) {
					add_sel(cli);
					break;
				}
			}
		}
	}
}

static void
cmd_select(char const *args)
{
	char *token;
	char *str = strdupa(args);

	// Clear the old selection.
	unordered_set<Client *>().swap(Selection);

	if (!*args) {
		output("Selection cleared.\n");
		return;
	}

	token = strtok(str, "\t ");
	while (token) {
		switch (token[0]) {
		case '<':
		case '>':
			select_by_msg(token);
			break;
		case '*':
			select_all();
			break;
		case '=':
			select_active();
			break;
		case '%':
			select_by_matchrule(token + 1);
			break;
		case '@':
			select_by_owned_name(token + 1);
			break;
		case '0' ... '9': {
			char *end;
			pid_t pid = strtoul(token, &end, 10);
			if (!*end) {
				select_by_pid(pid);
				break;
			}
			/* fall through */
		}
		case 's':
		case 'y':
			if (token[1] == ':') {
				select_by_unique_name(token);
				break;
			}
			/* fall through more */
		default:
			select_by_cmdline(token);
			break;
		}
		token = strtok(NULL, "\t ");
	}
	output("Selected %zu client(s).\n", Selection.size());
}

static void
cmd_help(char const *args)
{
	if (!*args || strstr("commands", args))
	{
		printf("\nAVAILABLE COMMANDS\n\n");
		foreach (ci, Commands)
			ci->second.print_brief();
	} else if (strstr("columns", args))
	{
		printf("\nAVAILABLE COLUMNS\n\n");
		for (int i = 0; i < NColumns; ++i) {
			Column const &col = Columns[i];
			printf("%2d. %-8s -- %s\n",
			       i+1, col.header, col.desc);
		}
	} else {
		int arglen = strlen(args);
		foreach (ci, Commands) {
			if (!strncmp(ci->first.c_str(), args, arglen)) {
				ci->second.print_help();
				break;
			}
		}
	}
}

static void
cmd_quit(char const *args)
{
	Alive = false;
	shutdown_interactive();
}

static void
cmd_monitor(char const *args)
{
	if (!bool_fromarg(args, Monitor))
		return;
	output("Monitor mode: %s.\n", Monitor ? "on" : "off");
}

static void
cmd_autorefresh(char const *args)
{
	if (!*args) {
		Autorefresh = !Autorefresh;
	} else {
		char *end;
		unsigned long t;
		t = strtoul(args, &end, 10);
		if (!*end && t > 2) {
			ms_to_tv(&Trefresh, t);
			Autorefresh = true;
		} else if (!bool_fromarg(args, Autorefresh))
			return;
	}
	output("Autorefresh: %s",
	       Autorefresh ? "on" : "off");
	if (Autorefresh)
		output(" (%dms)", tv_to_ms(&Trefresh));
	output(".\n");
	if (Autorefresh) {
		if (Interactive) {
			rl_callback_handler_remove();
			rl_prep_terminal(1);
		}
		gettimeofday(&Tnext, NULL);
	}
}

static void
cmd_annotate(char const *args)
{
	static char buf[128];
	if (!*args) {
		struct tm *t;
		time_t now = time(NULL);
		t = localtime(&now);
		strftime(buf, sizeof(buf), "%F %T", t);
		args = buf;
	}
	int i = printf("-- %s ", args);
	int m = Interactive ? Winsize.ws_col : 78;
	while (i++ < m) putchar('-');
	putchar('\n');
}

static void
cmd_setcolumns(char const *args)
{
	if (*args) {
		set<int> newcols;
		char *token;
		char *str = strdupa(args);

		token = strtok(str, "\t ");
		while (token) {
			// '*' is all columns
			if (token[0] == '*') {
				for (int i = 0; i < NColumns; ++i)
					newcols.insert(i);
				break;
			}
			// try as index
			char *end;
			int col = strtol(token, &end, 10);
			if (!*end && 1 <= col && col <= NColumns) {
				newcols.insert(col - 1);
				goto cont;
			}
			// try as string
			for (int i = 0; i < NColumns; ++i) {
				if (!strcasecmp(token, Columns[i].header)) {
					newcols.insert(i);
					break;
				}
			}
		cont:
			token = strtok(NULL, "\t ");
		}
		// don't clear all columns
		if (newcols.size())
			Active_columns.swap(newcols);
	}
	output("\nSELECTED COLUMNS\n\n");
	foreach (ci, Active_columns) {
		Column const &col = Columns[*ci];
		output("%2d. %-8s -- %s\n",
		       *ci+1, col.header, col.desc);
	}
}

static void
cmd_setsort(char const *args)
{
	if (*args) {
		char *end;
		int col;
		Sort_reverse = false;
		if (args[0] == '-') {
			Sort_reverse = true;
			++args;
		}
		col = strtoul(args, &end, 10);
		if (col < 1 || col > NColumns || *end) {
			// it was not a number
			col = -1;
			for (int i = 0; i < NColumns; ++i) {
				if (!strcasecmp(Columns[i].header, args)) {
					col = i;
					break;
				}
			}
			if (col >= 0)
				Sort_column = static_cast<ColumnId>(col);
		} else
			  Sort_column = static_cast<ColumnId>(col - 1);
	}
	output("Sort column: %2d. %s (%s).\n", Sort_column+1,
	       Columns[Sort_column].header, Sort_reverse ? "DESC" : "ASC");
}

static void
cmd_show_stats(char const *args)
{
	printf("GLOBAL STATISTICS\n"
	       "  total messages    %lu\n"
	       "  total bytes sent  %lu\n"
	       "  total wakeups     %lu\n",
	       Stats.total_messages,
	       Stats.total_bytes,
	       Stats.total_wakeups);
}

static void
cmd_ignore_replies(char const *args)
{
	if (!bool_fromarg(args, Ignore_replies))
		return;
	output("%s reply messages.\n", Ignore_replies ?
	       "Ignoring" : "Accounting also for");
}

static void
cmd_maint(char const *args)
{
	foreach (bi, Buses) {
		printf("** Peers (%zu)\n", (*bi)->peers.size());
		foreach (pi, (*bi)->peers)
			pi->second->dump(stdout);
		printf("** Rules\n");
		(*bi)->matchmaker.dump(stdout);
		printf("** Selection (%zu)\n", Selection.size());
		foreach (si, Selection)
			(*si)->dump(stdout);
		printf("** Stats\n"
		       "total_messages: %8lu\n"
		       "total_bytes:    %8lu\n"
		       "total_wakeups:  %8lu\n",
		       Stats.total_messages,
		       Stats.total_bytes,
		       Stats.total_wakeups);
		printf("** Destinations\n");
		foreach (di, (*bi)->destinations)
			printf("  %-24s => %p\n", di->first.c_str(),
			       di->second);
	}
}

static void
cmd_dups(char const *args)
{
	foreach (bi, Buses) {
		if (args[0] && args[0] != (*bi)->prefix)
			continue;
		multimap<pid_t, Client const *> seen;
		foreach (pi, (*bi)->peers) {
			Client const *c = pi->second;
			seen.insert(make_pair(c->pid, c));
		}
		for (auto si = seen.begin(), se = seen.end(); si != se;) {
			pid_t p = si->first;
			Client const *c = si->second;
			size_t nconn = seen.count(p);
			if (nconn > 1)
				printf("%zu connections on %s bus by %u %s\n",
				       nconn,
				       c->bus->bustype == DBUS_BUS_SYSTEM ?
				       "system" : "session",
				       p, c->cmdline.c_str());
			while (si->first == p)
				++si;
		}
	}
}

static void
cmd_takeover(char const *arg)
{
	if (Interactive) {
		output("Not for interactive use :)\n");
		return;
	}
	int end;
	sscanf(arg, "%u %n", &Giveway_pid, &end);
	arg += end;
	int f = open(arg, O_RDWR);
	if (f < 0) {
		log(1, "open '%s': %m\n", arg);
		return;
	}
	if (!isatty(f)) {
		log(1, "not a tty\n");
		return;
	}
	dup2(f, STDIN_FILENO);
	dup2(f, STDOUT_FILENO);
	dup2(f, STDERR_FILENO);
	if (Fifo)
		close(Fifo);
	Interactive = true;
	output("Assuming command.\n");
	setup_interactive();
}

static void noop(int signo) { }

/* Acts as a shell for resuming */
static void
giveway(char const *fifo)
{
	if (!isatty(STDIN_FILENO)) {
		fatal("not on a tty\n");
		return;
	}
	char b[256];
	int f = open(fifo, O_RDWR);
	if (f < 0) {
		fatal("open '%s': %m\n", fifo);
		return;
	}
	char *tty = ttyname(STDIN_FILENO);
	snprintf(b, sizeof(b), "takeover %u %s\n", getpid(), tty);
	ioctl(STDIN_FILENO, TIOCNOTTY, 0);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	write(f, b, strlen(b));
	close(f);
	signal(SIGUSR1, noop);
	pause();
	exit(0);
}

static char const *
viewkind(int uv)
{
	if (uv == ViewAll)
		return "all";
	if (uv == ViewActive)
		return "active";
	if (uv == ViewSelection)
		return "selected";
	return "?";
}

static void
cmd_setview(char const *arg)
{
	if (!*arg) {
		output("Need an argument, refer to the manual.\n");
		return;
	}
	bool done = false;
	size_t l = strlen(arg);

	if (!strncasecmp("all", arg, l))
		Use_view = ViewAll, done = true;
	else if (!strncasecmp("active", arg, l))
		Use_view = ViewActive, done = true;
	else if (!strncasecmp("selection", arg, l))
		Use_view = ViewSelection, done = true;
	if (done) {
		output("Viewing %s clients.\n", viewkind(Use_view));
		return;
	}

	if (!strncasecmp("totals", arg, l))
		Show_totals = true, done = true;
	else if (!strncasecmp("current", arg, l))
		Show_totals = false, done = true;
	if (done) {
		output("Showing '%s' counters.\n", Show_totals ?
		       "totals" : "current");
		return;
	}

	if (!strncasecmp("gone-last", arg, l))
		Gone_last = true, done = true;
	else if (!strncasecmp("gone-mixed", arg, l))
		Gone_last = false, done = true;
	if (done) {
		output("Showing exited clients %s living ones.\n",
		       Gone_last ?
		       "after" : "mixed with");
		return;
	}
	output("Invalid argument.\n");
}

static void
add_command(char const *name, char const *args,
	    Command_fn fn, char const *desc, char const *help = NULL)
{
	Commands.insert(make_pair(name, Command(name, args, fn, desc, help)));
}

static void
setup_ui()
{
	add_command("help", NULL, cmd_help,
		    "print help",
		    "see 'help help'");
	add_command("?", NULL, cmd_help,
		    "print help",
		    "see 'help help'");
	add_command("quit", NULL, cmd_quit,
		    "back to reality");
	add_command("overview", NULL, cmd_overview,
		    "print the overview of all clients");
	add_command("details", "[WHAT]", cmd_details,
		    "print details of selected clients",
		    "WHAT may be one or more of: brief, names, counters, "
		    "messages, rules or all.");
	add_command("reset", "[all]", reset_clients,
		    "reset current (or all) counters");
	add_command("monitor", "[BOOLEAN]", cmd_monitor,
		    "set or toggle monitor mode");
	add_command("auto", "[BOOLEAN|INTERVAL]", cmd_autorefresh,
		    "toggle autorefresh");
	add_command("log", "[TEXT]", cmd_annotate,
		    "annotate the output");
	add_command("--", "[TEXT]", cmd_annotate,
		    "annotate the output");
	add_command("select", "[CRITERIA...]", cmd_select,
		    "select clients based on criteria");
	add_command("order", "[COLUMN]", cmd_setsort,
		    "set sort column");
	add_command("columns", "[COLUMNS...]", cmd_setcolumns,
		    "set visible columns");
	add_command("gstats", NULL, cmd_show_stats,
		    "show global statistics");
	add_command("ignore-replies", NULL, cmd_ignore_replies,
		    "set or toggle ignoring replies");
	add_command("view", "OPTION", cmd_setview,
		    "set what and how gets shown",
		    "OPTION is: \n"
		    "  [all|active|selection] selects the set of clients\n"
		    "  [totals|current] chooses the counters to be shown\n"
		    "  [gone-last|gone-mixed] decides how to sort "
		    "exited clients");
	add_command("dups", "[s|y]", cmd_dups,
		    "print processes with more than one connection per bus");
	add_command("maintenance", NULL, cmd_maint,
		    "maintenance command");
	add_command("takeover", NULL, cmd_takeover, "");

	// setup columns
	Active_columns.insert(CPid);
	Active_columns.insert(CUniqueName);
	Active_columns.insert(CNrMatchrules);
	Active_columns.insert(COutMessages);
	Active_columns.insert(CInMessages);
	Active_columns.insert(CWakeups);
	Active_columns.insert(CPerWk);
	Active_columns.insert(CPerOutMessages);
	Active_columns.insert(CCmdline);

	Sort_column = COutMessages;
	Sort_reverse = true;
}

static void
process_command(char *input)
{
	// assert(len > 0);
	// trim both sides
	while (*input && isspace(*input)) ++input;
	int last = strlen(input) - 1;
	while (last >= 0 && isspace(input[last])) --last;
	input[last+1] = '\0';

	// First word is the command,
	char const *t = input;
	while (*t && !isspace(*t)) ++t;
	int cmdlen = t - input;
	// the rest are arguments.
	while (*t && isspace(*t)) ++t;
	char const *args = t;

	// An empty command is equivalent to 'overview'...
	if (last < 0)
		return cmd_overview(args);
	// ... otherwise try to find an unambiguous prefix.
	list<Command const *> candidates;
	foreach (ci, Commands) {
		if (!strncmp(ci->first.c_str(), input, cmdlen))
			candidates.push_back(&ci->second);
	}
	if (candidates.size() == 0)
		printf("Unknown command, type 'help' for help.\n");
	else if (candidates.size() > 1) {
		printf("Ambiguous input:");
		foreach (ci, candidates)
			printf(" %s", (*ci)->name);
		putchar('\n');
	} else
		(*candidates.begin())->func(args);
}

static void
have_command(char *cmd)
{
	if (!cmd) {
		if (Interactive) {
			putchar('\n');
			cmd_quit("");
		}
		Stdin_eof = true;
		return;
	}
	if (*cmd)
		add_history(cmd);
	ansi(GOTO_COL_1 CLEAR_EOL);
	process_command(cmd);
	free(cmd);
}

static void
process_top_command(char cmd)
{
	switch (cmd) {
	case 'a':
		Use_view = (Use_view + 1) % ViewLast;
		output("Use view %d\n", Use_view);
		break;
	case '\004': // Ctrl-d
	case 'q':
		Autorefresh = false;
		rl_deprep_terminal();
		rl_callback_handler_install(RL_PROMPT, have_command);
		break;
	case 'r':
		reset_clients("");
		break;
	case '<':
		for (auto ai = Active_columns.begin(),
			     ae = Active_columns.end();
		     ai != ae;)
		{
			auto pi = ai++;
			if (Sort_column <= *ai) {
				Sort_column = (ColumnId)*pi;
				break;
			}
		}
		break;
	case '>': {
		auto it = Active_columns.upper_bound(Sort_column);
		if (it != Active_columns.end())
			Sort_column = (ColumnId)*it;
		break;
	}
	case '-':
		Sort_reverse = !Sort_reverse;
		break;
	default:
		printf("%d\n", cmd);
		break;
	}
}

static void
print_top_view()
{
	ansi(GOTO_HOME);
	if (Interactive) {
		int w;
		w = printf("a - cycle all/active/selected, "
			   "r: reset counters, "
			   "<, >: move sort column, "
			   "-: reverse order, "
			   "q: stop autorefresh");
		printf("%*s\n", Winsize.ws_col - w,
		       viewkind(Use_view));
	}
	cmd_overview("");
	ansi(CLEAR_BOTTOM);
	fflush(stdout);
}

/* ------------------------
 * Option parsing, mainloop
 * ------------------------ */

static void
cleanup_control_fifo()
{
	unlink(Control_fifo);
}

// van, fifo: hasznaljuk
// van, nemfifo: fatal
// nincs: letrehoz, hasznal, letorol
static void
create_control_fifo(char const *name)
{
	struct stat sb;
	if (stat(name, &sb) < 0 && errno != ENOENT) {
		fatal("stat '%s': %m\n", name);
		return;
	}
	if (errno == ENOENT) {
		if (mkfifo(name, 0666) < 0) {
			fatal("mkfifo '%s': %m\n", name);
			return;
		}
		// Remember name to erase it later.
		Control_fifo = strdup(name);
		atexit(cleanup_control_fifo);
	} else if (!S_ISFIFO(sb.st_mode)) {
		fatal("'%s' already exists and not a fifo.\n", name);
		return;
	}
	if ((Fifo = open(name, O_RDWR)) < 0) {
		log(1, "open '%s': %m\n", name);
	} else {
		output("Using '%s' as input.\n", name);
		dup2(Fifo, STDIN_FILENO);
	}
}

static void
parse_options(int argc, char *argv[])
{
	static char const usage[] = "Usage: %s [OPTIONS]\n"
		"  -S, --session          use the session bus\n"
		"  -Y, --system           use the system bus\n"
		"  -B, --both             use both buses (default)\n"
		"  -v, --verbose          verbose output (stacks)\n"
		"  -k, --keep-stdin       keep stdin open and/or ignore EOF\n"
		"  -q, --quiet            don't announce commands\n"
		"  -c, --control FIFO     create and use control fifo\n"
		"  -t, --takeover FIFO    attach to instance using FIFO\n"
		"  -i, --interactive      force interactive mode\n";

	static char const short_opts[] = "SYBvkqc:t:i";
	static struct option long_opts[] = {
		{ "session",    no_argument, 0, 'S' },
		{ "system",     no_argument, 0, 'Y' },
		{ "both",       no_argument, 0, 'B' },
		{ "verbose",    no_argument, 0, 'v' },
		{ "keep-stdin", no_argument, 0, 'k' },
		{ "quiet",      no_argument, 0, 'q' },
		{ "control",    required_argument, 0, 'c' },
		{ "takeover",   required_argument, 0, 't' },
		{ "interactive",required_argument, 0, 'i' },
		{ 0, 0, 0, 0 }
	};

	bool force_interactive = false;
	while (1) {
		int c = getopt_long(argc, argv,
				    short_opts, long_opts, NULL);
		if (c == -1) break;
		switch (c) {
		case 'B': Buses.push_back(new BusConnection(DBUS_BUS_SYSTEM));
			/*FALL THROUGH*/
		case 'S': Buses.push_back(new BusConnection(DBUS_BUS_SESSION));
			break;
		case 'Y': Buses.push_back(new BusConnection(DBUS_BUS_SYSTEM));
			break;
		case 'v': Verbosity++; break;
		case 'k': Keep_stdin = true; break;
		case 'q': Quiet = true; break;
		case 'c': create_control_fifo(optarg); break;
		case 't': giveway(optarg); break;
		case 'i': force_interactive = true;
		default:
			fprintf(stderr, usage, argv[0]);
			exit(1);
			break;
		}
	}
	if (!Buses.size()) {
		Buses.push_back(new BusConnection(DBUS_BUS_SYSTEM));
		Buses.push_back(new BusConnection(DBUS_BUS_SESSION));
	}
	Interactive = force_interactive ||
		(isatty(STDIN_FILENO) && isatty(STDOUT_FILENO));

	output("%s mode.\n", Interactive ? "Interactive" : "Batch");
	output("Listening on %s.\n", Buses.size() == 2 ?
	       "both buses" : (Buses[0]->bustype == DBUS_BUS_SYSTEM ?
			       "system bus" : "session bus"));
}

static void
mainloop()
{
	int nfds = Buses.size() + 1;
	struct pollfd fds[nfds];
	size_t fdi;
	for (fdi = 0; fdi < Buses.size(); ++fdi) {
		fds[fdi].fd = Buses[fdi]->busfd;
		fds[fdi].events = POLLIN | POLLHUP;
	}
	fds[fdi].fd = STDIN_FILENO;
	fds[fdi].events = POLLIN | POLLHUP;

	Last_reset = Last_event;
	int timeout = -1;
	while (Alive) {
		int nready;
		do nready = poll(fds, nfds, timeout);
		while (nready == -1 && errno == EINTR && Alive);
		if (!Alive)
			break;
		if (nready < 0) {
			log(2, "poll: %m\n");
			break;
		}

		if (fds[fdi].revents & POLLHUP)
			Stdin_eof = true;
		if (fds[fdi].revents & POLLIN) {
			if (Interactive) {
				if (!Autorefresh)
					rl_callback_read_char();
				else {
					// char based input when autorefresh
					char c;
					if (read(STDIN_FILENO, &c, 1) == 0)
						Stdin_eof = true;
					else
						process_top_command(c);
				}
			} else {
				// noninteractive fgets-like input
				char *cmd;
				refill();

				while ((cmd = ngets()))
					process_command(cmd);
			}
		}
		if (Stdin_eof) {
			Stdin_eof = false;
			if (Keep_stdin) {
				--nfds;
				fds[fdi].revents = 0;
				continue;
			} else
				break;
		}

		for (size_t i = 0; i < Buses.size(); ++i)
			if (fds[i].revents & POLLIN) {
				DBusConnection *c = Buses[i]->conn;
				dbus_connection_read_write(c, 0);
				while (dbus_connection_dispatch(c) ==
				       DBUS_DISPATCH_DATA_REMAINS);
			}

		if (Autorefresh) {
			// woken up, check if we need todraw
			struct timeval tnow;
			gettimeofday(&tnow, NULL);
			if (!timercmp(&tnow, &Tnext, <)) {
				// A refresh is due.
				print_top_view();
				timeradd(&tnow, &Trefresh, &Tnext);
			}
			// before we sleep we need to know howmuch
			struct timeval trem;
			timersub(&Tnext, &tnow, &trem);
			timeout = tv_to_ms(&trem);
			if (timeout < 0)
				timeout = 0;
		} else
			timeout = -1;
	}
}

static void
setup_interactive()
{
	if (!Interactive) {
		// lose the ctty
		int f;
		if ((f = open("/dev/tty", O_WRONLY))) {
			ioctl(f, TIOCNOTTY, 0);
			close(f);
		}
		return;
	}
	ioctl(0, TIOCGWINSZ, &Winsize);
	signal(SIGWINCH, sighandler);
	rl_callback_handler_install(RL_PROMPT, have_command);
	rl_completion_entry_function = complete_command;
}

static void
shutdown_interactive()
{
	if (!Interactive)
		return;
	rl_callback_handler_remove();
	rl_deprep_terminal();
	if (Giveway_pid)
		kill(Giveway_pid, SIGUSR1);
}

int
MAIN(int argc, char *argv[])
{
	static char stbuf[1024];

	parse_options(argc, argv);
	setup_ui();
	setup_dbus();
	if (Interactive)
		output(Initial_help);
	signal(SIGINT, sighandler);
	setvbuf(stdout, stbuf, _IOLBF, sizeof(stbuf));
	setup_interactive();

	mainloop();

	shutdown_interactive();
	shutdown_dbus();
	return 0;
}

#if TESTS
/* -----
 * Tests
 * ----- */

#include <assert.h>

struct Msgen {
	static Msgen method_call()
		{ return Msgen(DBUS_MESSAGE_TYPE_METHOD_CALL); }
	static Msgen method_return()
		{ return Msgen(DBUS_MESSAGE_TYPE_METHOD_RETURN); }
	static Msgen signal()
		{ return Msgen(DBUS_MESSAGE_TYPE_SIGNAL); }
	static Msgen error()
		{ return Msgen(DBUS_MESSAGE_TYPE_ERROR); }

	Msgen() {}
	Msgen(int type) { msg = dbus_message_new(type); }
	Msgen &sender(char const *v)
		{ return dbus_message_set_sender(msg, v), *this; }
	Msgen &dest(char const *v)
		{ return dbus_message_set_destination(msg, v), *this; }
	Msgen &path(char const *v)
		{ return dbus_message_set_path(msg, v), *this; }
	Msgen &interface(char const *v)
		{ return dbus_message_set_interface(msg, v), *this; }
	Msgen &member(char const *v)
		{ return dbus_message_set_member(msg, v), *this; }
	Msgen &arg(char const *v)
		{
			initer();
			dbus_message_iter_append_basic(&iter,
						       DBUS_TYPE_STRING, &v);
			return *this;
		}
	Msgen &arg(int v)
		{
			initer();
			dbus_message_iter_append_basic(&iter,
						       DBUS_TYPE_INT32, &v);
			return *this; }
	Msgen &arg(bool v)
		{
			initer();
			dbus_message_iter_append_basic(&iter,
						       DBUS_TYPE_BOOLEAN, &v);
			return *this;
		}

	void initer() { dbus_message_iter_init_append(msg, &iter); }
	operator DBusMessage *() { return msg; }
	DBusMessage *msg;
	DBusMessageIter iter;
};

static void
test_matchrule()
{
	Matchrule *r;
#define MAKER(rule) assert(r = Matchrule::create(rule)); r->dump(stderr)
#define ACCEPTS(x) assert(r->applies(x))
#define REJECTS(x) assert(not r->applies(x))
	MAKER("");
	assert(r->flags == 0);
	ACCEPTS(Msgen::method_call().interface("x.y.z").member("bar"));
	ACCEPTS(Msgen::signal().member("qqq").path("/foo/bar"));

	MAKER("type='signal'");
	assert(r->flags == Matchrule::HasType);
	assert(r->type == DBUS_MESSAGE_TYPE_SIGNAL);
	REJECTS(Msgen::method_call().interface("x.y.foo").member("bar"));
	REJECTS(Msgen::error().member("argh").arg("foo"));
	REJECTS(Msgen::method_return().member("argh").arg("foo"));
	ACCEPTS(Msgen::signal().path("/foo/bar"));
	ACCEPTS(Msgen::signal().member("qqq"));
	ACCEPTS(Msgen::signal().interface("x.y.z").member("qqq"));

	assert(not Matchrule::create("asdfas"));

	MAKER("interface='foo.bar'   , type='method_call'");
	assert(r->flags == (Matchrule::HasType | Matchrule::HasInterface));
	assert(r->type == DBUS_MESSAGE_TYPE_METHOD_CALL);
	assert(r->interface == "foo.bar");
	ACCEPTS(Msgen::method_call().interface("foo.bar"));
	REJECTS(Msgen::method_call().interface("x.y.z"));
	ACCEPTS(Msgen::method_call().interface("foo.bar").member("a"));
	ACCEPTS(Msgen::method_call().interface("foo.bar").member("b"));
	REJECTS(Msgen::signal().interface("x.y.z"));

	MAKER("type='error',	 arg0  ='blaa'   ");
	assert(r->flags == (Matchrule::HasType | Matchrule::HasArgs));
	assert(r->type == DBUS_MESSAGE_TYPE_ERROR);
	assert(r->args.size() == 1);
	assert(r->args[0] == "blaa");
	ACCEPTS(Msgen::error().member("foo").arg("blaa"));
	REJECTS(Msgen::error().member("foo").arg("quux"));
	REJECTS(Msgen::error().member("bar").arg("quux").arg("blaa"));

	MAKER("arg3 ='blaa' , arg1=  'foo'");
	assert(r->flags == Matchrule::HasArgs);
	assert(r->args.size() == 2);
	assert(r->args[1] == "foo");
	assert(r->args[3] == "blaa");
	REJECTS(Msgen::signal().member("xyz").arg("0").arg("1")
		.arg("2").arg("3"));
	ACCEPTS(Msgen::signal().member("xyz").arg("0").arg("foo")
		.arg("2").arg("blaa"));
	REJECTS(Msgen::signal().member("xyz").arg("0").arg("foo")
		.arg("2").arg("3"));
	REJECTS(Msgen::signal().member("xyz").arg("0").arg("foo")
		.arg("2").arg("blaargh"));

	assert(not Matchrule::create("arg64='toomany'"));

	MAKER("sender='x.y'");
	assert(r->flags == Matchrule::HasSender);
	REJECTS(Msgen::signal());
	ACCEPTS(Msgen::signal().sender("x.y"));
	ACCEPTS(Msgen::method_call().sender("x.y"));
	ACCEPTS(Msgen::method_call().sender("x.y").arg("quux"));
	REJECTS(Msgen::error().dest("x.y.z"));

#undef REJECTS
#undef ACCEPTS
#undef MAKER
}

int
TEST_MAIN(int argc, char *argv[])
{
	Verbosity = 5;
	test_matchrule();
	return 0;
}
#endif
