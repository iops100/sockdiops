#include "common.h"
#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20130304

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)


#ifndef yyparse
#define yyparse    socks_yyparse
#endif /* yyparse */

#ifndef yylex
#define yylex      socks_yylex
#endif /* yylex */

#ifndef yyerror
#define yyerror    socks_yyerror
#endif /* yyerror */

#ifndef yychar
#define yychar     socks_yychar
#endif /* yychar */

#ifndef yyval
#define yyval      socks_yyval
#endif /* yyval */

#ifndef yylval
#define yylval     socks_yylval
#endif /* yylval */

#ifndef yydebug
#define yydebug    socks_yydebug
#endif /* yydebug */

#ifndef yynerrs
#define yynerrs    socks_yynerrs
#endif /* yynerrs */

#ifndef yyerrflag
#define yyerrflag  socks_yyerrflag
#endif /* yyerrflag */

#ifndef yylhs
#define yylhs      socks_yylhs
#endif /* yylhs */

#ifndef yylen
#define yylen      socks_yylen
#endif /* yylen */

#ifndef yydefred
#define yydefred   socks_yydefred
#endif /* yydefred */

#ifndef yydgoto
#define yydgoto    socks_yydgoto
#endif /* yydgoto */

#ifndef yysindex
#define yysindex   socks_yysindex
#endif /* yysindex */

#ifndef yyrindex
#define yyrindex   socks_yyrindex
#endif /* yyrindex */

#ifndef yygindex
#define yygindex   socks_yygindex
#endif /* yygindex */

#ifndef yytable
#define yytable    socks_yytable
#endif /* yytable */

#ifndef yycheck
#define yycheck    socks_yycheck
#endif /* yycheck */

#ifndef yyname
#define yyname     socks_yyname
#endif /* yyname */

#ifndef yyrule
#define yyrule     socks_yyrule
#endif /* yyrule */
#define YYPREFIX "socks_yy"

#define YYPURE 0

#line 46 "config_parse.y"

#include "yacconfig.h"

#if !SOCKS_CLIENT

#include "monitor.h"

#endif /* !SOCKS_CLIENT */

static const char rcsid[] =
"$Id: config_parse.y,v 1.703.4.8.2.8 2017/01/31 08:17:38 karls Exp $";

#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
   extern jmp_buf tcpd_buf;
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

extern void yyrestart(FILE *fp);

typedef enum { from, to, bounce } addresscontext_t;

static int
ipaddr_requires_netmask(const addresscontext_t context,
                        const objecttype_t objecttype);
/*
 * Returns true if an ipaddress used in the context of "objecttype" requires
 * a netmask, or false otherwise.
 *
 * "isfrom" is true if the address is to be used in the source/from
 * context, and false otherwise.
 */

static void
addnumber(size_t *numberc, long long *numberv[], const long long number);

static void
addrinit(ruleaddr_t *addr, const int netmask_required);

static void
gwaddrinit(sockshost_t *addr);

static void
routeinit(route_t *route);

#if SOCKS_CLIENT
static void parseclientenv(int *haveproxyserver);
/*
 * parses client environment, if any.
 * If a proxy server is configured in environment, "haveproxyserver" is set
 * to true upon return.  If not, it is set to false.
 */

static char *serverstring2gwstring(const char *server, const int version,
                                   char *gw, const size_t gwsize);
/*
 * Converts a gateway specified in environment to the format expected
 * in a socks.conf file.
 * "server" is the address specified in the environment,
 * "version" the kind of server address,
 * "gw", of size "gwsize", is the string to store the converted address in.
 *
 * Returns "gw" on success, exits on error.
 */

#define alarminit()
#define SET_TCPOPTION(logobject, level, attr)

#else /* !SOCKS_CLIENT */

/*
 * Reset pointers to point away from object-specific memory to global
 * memory.  Should be called after adding the object.
 */
static void post_addrule(void);

/*
 * Sets up various things after a object has been parsed, but before it has
 * been added.  Should be called before adding the object.
 *
 */
static void pre_addrule(struct rule_t *rule);
static void pre_addmonitor(monitor_t *monitor);

/*
 * Prepare pointers to point to the correct memory for adding a
 * new objects.  Should always be called once we know what type of
 * object we are dealing with.
 */
static void ruleinit(rule_t *rule);
static void monitorinit(monitor_t *monitor);
static void alarminit(void);

static int configure_privileges(void);
/*
 * Sets up privileges/userids.
 */

static int
checkugid(uid_t *uid, gid_t *gid, unsigned char *isset, const char *type);

#define SET_TCPOPTION(tcp, level, attr)                                        \
do {                                                                           \
   (tcp)->isconfigured              = 1;                                       \
                                                                               \
   (tcp)->attr                      = 1;                                       \
   (tcp)->__CONCAT(attr, _loglevel) = cloglevel;                               \
} while (/* CONSTCOND */ 0)

/*
 * Let commandline-options override configfile-options.
 * Currently there's only one such option.
 */
#define LOG_CMDLINE_OVERRIDE(name, newvalue, oldvalue, fmt)                    \
do {                                                                           \
   slog(LOG_NOTICE,                                                            \
        "%s: %s commandline value \"" fmt "\" overrides "                      \
        "config-file value \"" fmt "\" set in file %s",                        \
        function, name, (newvalue), (oldvalue), sockscf.option.configfile);    \
} while (/* CONSTCOND */ 0 )

#define CMDLINE_OVERRIDE(cmdline, option)                                      \
do {                                                                           \
   if ((cmdline)->debug_isset) {                                               \
      if ((option)->debug != (cmdline)->debug)                                 \
         LOG_CMDLINE_OVERRIDE("debug",                                         \
                              (cmdline)->debug,                                \
                              (option)->debug,                                 \
                              "%d");                                           \
                                                                               \
      (option)->debug      = (cmdline)->debug;                                 \
      (option)->debug_isset= (cmdline)->debug_isset;                           \
   }                                                                           \
} while (/* CONSTCOND */ 0)

#endif /* !SOCKS_CLIENT */

extern int  yylineno;
extern char *yytext;
extern char currentlexline[];
extern char previouslexline[];

static const char *function = "configparsing()";

/*
 * Globals because used by functions for reporting parsing errors in
 * parse_util.c
 */
unsigned char   *atype;         /* atype of new address.               */
unsigned char  parsingconfig;   /* currently parsing config?          */

/*
 * for case we are unable to (re-)open logfiles operator specifies.
 */

#if !SOCKS_CLIENT
static logtype_t       old_log,           old_errlog;
#endif /* !SOCKS_CLIENT */

static int             failed_to_add_log, failed_to_add_errlog;

static unsigned char   add_to_errlog;   /* adding file to errlog or regular?  */

static objecttype_t    objecttype;      /* current object_type we are parsing.*/


#if !SOCKS_CLIENT
static  logspecial_t                *logspecial;
static warn_protocol_tcp_options_t  *tcpoptions;

static interfaceprotocol_t *ifproto;  /* new interfaceprotocol settings.      */

static monitor_t       monitor;       /* new monitor.                         */
static monitor_if_t    *monitorif;    /* new monitor interface.               */
static int             *alarmside;    /* data-side to monitor (read/write).   */

static int             cloglevel;     /* current loglevel.                    */

static rule_t          rule;          /* new rule.                            */

static shmem_object_t  ss;
static int session_isset;
static shmem_object_t  bw;
static int bw_isset;


#endif /* !SOCKS_CLIENT */

static unsigned char   *hostidoption_isset;

static long long       *numberv;
static size_t          numberc;

#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
static unsigned char   *hostindex;
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID  */

static timeout_t       *timeout = &sockscf.timeout;           /* default.     */

static socketoption_t  socketopt;

static serverstate_t   *state;
static route_t         route;         /* new route.                           */
static sockshost_t     gw;            /* new gateway.                         */

static ruleaddr_t      src;            /* new src.                            */
static ruleaddr_t      dst;            /* new dst.                            */
static ruleaddr_t      hostid;         /* new hostid.                         */
static ruleaddr_t      rdr_from;       /* new redirect from.                  */
static ruleaddr_t      rdr_to;         /* new redirect to.                    */

#if BAREFOOTD
static ruleaddr_t      bounceto;       /* new bounce-to address.              */
#endif /* BAREFOOTD */

static ruleaddr_t      *ruleaddr;      /* current ruleaddr                    */
static extension_t     *extension;     /* new extensions                      */


static struct in_addr  *ipv4;          /* new ip address                      */
static struct in_addr  *netmask_v4;    /* new netmask                         */

static struct in6_addr *ipv6;          /* new ip address                      */
static unsigned int    *netmask_v6;    /* new netmask                         */
static uint32_t        *scopeid_v6;    /* new scopeid.                        */

static struct in_addr  *ipvany;        /* new ip address                      */
static struct in_addr  *netmask_vany;  /* new netmask                         */

static int             netmask_required;/*
                                         * netmask required for this
                                         * address?
                                         */
static char            *domain;        /* new domain.                         */
static char            *ifname;        /* new ifname.                         */
static char            *url;           /* new url.                            */

static in_port_t       *port_tcp;      /* new TCP port number.                */
static in_port_t       *port_udp;      /* new UDP port number.                */

static int             *cmethodv;      /* new client authmethods.             */
static size_t          *cmethodc;      /* number of them.                     */
static int             *smethodv;      /* new socks authmethods.              */
static size_t          *smethodc;      /* number of them.                     */

static enum operator_t *operator;      /* new port operator.                  */

#if HAVE_GSSAPI
static char            *gssapiservicename; /* new gssapiservice.              */
static char            *gssapikeytab;      /* new gssapikeytab.               */
static gssapi_enc_t    *gssapiencryption;  /* new encryption status.          */
#endif /* HAVE_GSSAPI */

#if !SOCKS_CLIENT && HAVE_LDAP
static ldap_t          *ldap;        /* new ldap server details.              */
#endif /* SOCKS_SERVER && HAVE_LDAP */

#if DEBUG
#define YYDEBUG 1
#endif /* DEBUG */

#define ADDMETHOD(method, methodc, methodv)                                    \
do {                                                                           \
   if (methodisset((method), (methodv), (methodc)))                            \
      yywarnx("duplicate method: %s.  Already set on this methodline",         \
              method2string((method)));                                        \
   else {                                                                      \
      if ((methodc) >= METHODS_KNOWN) {                                        \
         yyerrorx("too many authmethods (%lu, max is %ld)",                    \
                  (unsigned long)(methodc), (long)METHODS_KNOWN);              \
         SERRX(methodc);                                                       \
      }                                                                        \
                                                                               \
      /*                                                                       \
       * check if we have the external libraries required for the method.      \
       */                                                                      \
      switch (method) {                                                        \
         case AUTHMETHOD_BSDAUTH:                                              \
            if (!HAVE_BSDAUTH)                                                 \
               yyerrorx_nolib("bsdauth");                                      \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_GSSAPI:                                               \
            if (!HAVE_GSSAPI)                                                  \
               yyerrorx_nolib("GSSAPI");                                       \
                                                                               \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_RFC931:                                               \
            if (!HAVE_LIBWRAP)                                                 \
               yyerrorx_nolib("libwrap");                                      \
            break;                                                             \
                                                                               \
         case AUTHMETHOD_PAM_ANY:                                              \
         case AUTHMETHOD_PAM_ADDRESS:                                          \
         case AUTHMETHOD_PAM_USERNAME:                                         \
            if (!HAVE_PAM)                                                     \
               yyerrorx_nolib("PAM");                                          \
            break;                                                             \
                                                                               \
      }                                                                        \
                                                                               \
      methodv[(methodc)++] = method;                                           \
   }                                                                           \
} while (0)

#define ASSIGN_NUMBER(number, op, checkagainst, object, issigned)              \
do {                                                                           \
   if (!((number) op (checkagainst)))                                          \
      yyerrorx("number (%lld) must be " #op " %lld (" #checkagainst ")",       \
               (long long)(number), (long long)(checkagainst));                \
                                                                               \
   if (issigned) {                                                             \
      if ((long long)(number) < minvalueoftype(sizeof(object)))                \
         yyerrorx("number %lld is too small.  Minimum is %lld",                \
                  (long long)number, minvalueoftype(sizeof(object)));          \
                                                                               \
      if ((long long)(number) > maxvalueoftype(sizeof(object)))                \
         yyerrorx("number %lld is too large.  Maximum is %lld",                \
                  (long long)number,  maxvalueoftype(sizeof(object)));         \
   }                                                                           \
   else  {                                                                     \
      if ((unsigned long long)(number) < uminvalueoftype(sizeof(object)))      \
         yyerrorx("number %llu is too small.  Minimum is %llu",                \
                  (unsigned long long)number, uminvalueoftype(sizeof(object)));\
                                                                               \
      if ((unsigned long long)(number) > umaxvalueoftype(sizeof(object)))      \
         yyerrorx("number %llu is too large.  Maximum is %llu",                \
                  (unsigned long long)number, umaxvalueoftype(sizeof(object)));\
   }                                                                           \
                                                                               \
   (object) = (number);                                                        \
} while (0)

#define ASSIGN_PORTNUMBER(portnumber, object)                                  \
do {                                                                           \
   /* includes 0 and MAXPORT because the exp might be "> 0" or "< MAXPORT". */ \
   ASSIGN_NUMBER(portnumber, >=,  0,         (object), 0);                     \
   ASSIGN_NUMBER(portnumber, <=, IP_MAXPORT, (object), 0);                     \
                                                                               \
   (object) = htons((in_port_t)(portnumber));                                  \
} while (0)

#define ASSIGN_THROTTLE_SECONDS(number, obj, issigned)     \
            ASSIGN_NUMBER((number), >, 0, obj, issigned)
#define ASSIGN_THROTTLE_CLIENTS(number, obj, issigned)     \
            ASSIGN_NUMBER((number), >, 0, obj, issigned)
#define ASSIGN_MAXSESSIONS(number, obj, issigned)          \
            ASSIGN_NUMBER((number), >, 0, obj, issigned)
#line 396 "config_parse.y"
#ifdef YYSTYPE
#undef  YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
#endif
#ifndef YYSTYPE_IS_DECLARED
#define YYSTYPE_IS_DECLARED 1
typedef union {
   struct {
      uid_t   uid;
      gid_t   gid;
   } uid;

   struct {
      valuetype_t valuetype;
      const int   *valuev;
   } error;

   struct {
      const char *oldname;
      const char *newname;
   } deprecated;

   char       *string;
   int        method;
   long long  number;
} YYSTYPE;
#endif /* !YYSTYPE_IS_DECLARED */
#line 475 "config_parse.c"

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
# ifdef YYPARSE_PARAM_TYPE
#  define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
# else
#  define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
# endif
#else
# define YYPARSE_DECL() yyparse(void)
#endif

/* Parameters sent to lex. */
#ifdef YYLEX_PARAM
# define YYLEX_DECL() yylex(void *YYLEX_PARAM)
# define YYLEX yylex(YYLEX_PARAM)
#else
# define YYLEX_DECL() yylex(void)
# define YYLEX yylex()
#endif

/* Parameters sent to yyerror. */
#ifndef YYERROR_DECL
#define YYERROR_DECL() yyerror(const char *s)
#endif
#ifndef YYERROR_CALL
#define YYERROR_CALL(msg) yyerror(msg)
#endif

extern int YYPARSE_DECL();

#define ALARM 257
#define ALARMTYPE_DATA 258
#define ALARMTYPE_DISCONNECT 259
#define ALARMIF_INTERNAL 260
#define ALARMIF_EXTERNAL 261
#define TCPOPTION_DISABLED 262
#define ECN 263
#define SACK 264
#define TIMESTAMPS 265
#define WSCALE 266
#define MTU_ERROR 267
#define CLIENTCOMPATIBILITY 268
#define NECGSSAPI 269
#define CLIENTRULE 270
#define HOSTIDRULE 271
#define SOCKSRULE 272
#define COMPATIBILITY 273
#define SAMEPORT 274
#define DRAFT_5_05 275
#define CONNECTTIMEOUT 276
#define TCP_FIN_WAIT 277
#define CPU 278
#define MASK 279
#define SCHEDULE 280
#define CPUMASK_ANYCPU 281
#define DEBUGGING 282
#define DEPRECATED 283
#define ERRORLOG 284
#define LOGOUTPUT 285
#define LOGFILE 286
#define LOGTYPE_ERROR 287
#define LOGTYPE_TCP_DISABLED 288
#define LOGTYPE_TCP_ENABLED 289
#define LOGIF_INTERNAL 290
#define LOGIF_EXTERNAL 291
#define ERRORVALUE 292
#define EXTENSION 293
#define BIND 294
#define PRIVILEGED 295
#define EXTERNAL_PROTOCOL 296
#define INTERNAL_PROTOCOL 297
#define EXTERNAL_ROTATION 298
#define SAMESAME 299
#define GROUPNAME 300
#define HOSTID 301
#define HOSTINDEX 302
#define INTERFACE 303
#define SOCKETOPTION_SYMBOLICVALUE 304
#define INTERNAL 305
#define EXTERNAL 306
#define INTERNALSOCKET 307
#define EXTERNALSOCKET 308
#define IOTIMEOUT 309
#define IOTIMEOUT_TCP 310
#define IOTIMEOUT_UDP 311
#define NEGOTIATETIMEOUT 312
#define LIBWRAP_FILE 313
#define LOGLEVEL 314
#define SOCKSMETHOD 315
#define CLIENTMETHOD 316
#define METHOD 317
#define METHODNAME 318
#define NONE 319
#define BSDAUTH 320
#define GSSAPI 321
#define PAM_ADDRESS 322
#define PAM_ANY 323
#define PAM_USERNAME 324
#define RFC931 325
#define UNAME 326
#define MONITOR 327
#define PROCESSTYPE 328
#define PROC_MAXREQUESTS 329
#define REALM 330
#define REALNAME 331
#define RESOLVEPROTOCOL 332
#define REQUIRED 333
#define SCHEDULEPOLICY 334
#define SERVERCONFIG 335
#define CLIENTCONFIG 336
#define SOCKET 337
#define CLIENTSIDE_SOCKET 338
#define SNDBUF 339
#define RCVBUF 340
#define SOCKETPROTOCOL 341
#define SOCKETOPTION_OPTID 342
#define SRCHOST 343
#define NODNSMISMATCH 344
#define NODNSUNKNOWN 345
#define CHECKREPLYAUTH 346
#define USERNAME 347
#define USER_PRIVILEGED 348
#define USER_UNPRIVILEGED 349
#define USER_LIBWRAP 350
#define WORD__IN 351
#define ROUTE 352
#define VIA 353
#define GLOBALROUTEOPTION 354
#define BADROUTE_EXPIRE 355
#define MAXFAIL 356
#define PORT 357
#define NUMBER 358
#define BANDWIDTH 359
#define BOUNCE 360
#define BSDAUTHSTYLE 361
#define BSDAUTHSTYLENAME 362
#define COMMAND 363
#define COMMAND_BIND 364
#define COMMAND_CONNECT 365
#define COMMAND_UDPASSOCIATE 366
#define COMMAND_BINDREPLY 367
#define COMMAND_UDPREPLY 368
#define ACTION 369
#define FROM 370
#define TO 371
#define GSSAPIENCTYPE 372
#define GSSAPIENC_ANY 373
#define GSSAPIENC_CLEAR 374
#define GSSAPIENC_INTEGRITY 375
#define GSSAPIENC_CONFIDENTIALITY 376
#define GSSAPIENC_PERMESSAGE 377
#define GSSAPIKEYTAB 378
#define GSSAPISERVICE 379
#define GSSAPISERVICENAME 380
#define GSSAPIKEYTABNAME 381
#define IPV4 382
#define IPV6 383
#define IPVANY 384
#define DOMAINNAME 385
#define IFNAME 386
#define URL 387
#define LDAPATTRIBUTE 388
#define LDAPATTRIBUTE_AD 389
#define LDAPATTRIBUTE_HEX 390
#define LDAPATTRIBUTE_AD_HEX 391
#define LDAPBASEDN 392
#define LDAP_BASEDN 393
#define LDAPBASEDN_HEX 394
#define LDAPBASEDN_HEX_ALL 395
#define LDAPCERTFILE 396
#define LDAPCERTPATH 397
#define LDAPPORT 398
#define LDAPPORTSSL 399
#define LDAPDEBUG 400
#define LDAPDEPTH 401
#define LDAPAUTO 402
#define LDAPSEARCHTIME 403
#define LDAPDOMAIN 404
#define LDAP_DOMAIN 405
#define LDAPFILTER 406
#define LDAPFILTER_AD 407
#define LDAPFILTER_HEX 408
#define LDAPFILTER_AD_HEX 409
#define LDAPGROUP 410
#define LDAPGROUP_NAME 411
#define LDAPGROUP_HEX 412
#define LDAPGROUP_HEX_ALL 413
#define LDAPKEYTAB 414
#define LDAPKEYTABNAME 415
#define LDAPDEADTIME 416
#define LDAPSERVER 417
#define LDAPSERVER_NAME 418
#define LDAPSSL 419
#define LDAPCERTCHECK 420
#define LDAPKEEPREALM 421
#define LDAPTIMEOUT 422
#define LDAPCACHE 423
#define LDAPCACHEPOS 424
#define LDAPCACHENEG 425
#define LDAPURL 426
#define LDAP_URL 427
#define LDAP_FILTER 428
#define LDAP_ATTRIBUTE 429
#define LDAP_CERTFILE 430
#define LDAP_CERTPATH 431
#define LIBWRAPSTART 432
#define LIBWRAP_ALLOW 433
#define LIBWRAP_DENY 434
#define LIBWRAP_HOSTS_ACCESS 435
#define LINE 436
#define OPERATOR 437
#define PAMSERVICENAME 438
#define PROTOCOL 439
#define PROTOCOL_TCP 440
#define PROTOCOL_UDP 441
#define PROTOCOL_FAKE 442
#define PROXYPROTOCOL 443
#define PROXYPROTOCOL_SOCKS_V4 444
#define PROXYPROTOCOL_SOCKS_V5 445
#define PROXYPROTOCOL_HTTP 446
#define PROXYPROTOCOL_UPNP 447
#define REDIRECT 448
#define SENDSIDE 449
#define RECVSIDE 450
#define SERVICENAME 451
#define SESSION_INHERITABLE 452
#define SESSIONMAX 453
#define SESSIONTHROTTLE 454
#define SESSIONSTATE_KEY 455
#define SESSIONSTATE_MAX 456
#define SESSIONSTATE_THROTTLE 457
#define RULE_LOG 458
#define RULE_LOG_CONNECT 459
#define RULE_LOG_DATA 460
#define RULE_LOG_DISCONNECT 461
#define RULE_LOG_ERROR 462
#define RULE_LOG_IOOPERATION 463
#define RULE_LOG_TCPINFO 464
#define STATEKEY 465
#define UDPPORTRANGE 466
#define UDPCONNECTDST 467
#define DNSRESOLVDST 468
#define USER 469
#define GROUP 470
#define VERDICT_BLOCK 471
#define VERDICT_PASS 472
#define YES 473
#define NO 474
#define YYERRCODE 256
static const short socks_yylhs[] = {                     -1,
  207,    0,    0,  126,  126,  125,  125,  125,  125,  125,
  124,  124,  123,  123,  123,  123,  123,  123,  123,  123,
  123,  123,  123,  123,  123,  123,  123,  123,  123,  123,
  123,  123,  123,  123,  123,  123,  123,  123,  123,  123,
  106,  209,  106,  210,  106,  211,  104,  212,  105,  213,
  205,  214,  206,  107,  208,  208,  215,  215,  215,  215,
  108,  108,  109,  138,  138,  138,  138,    5,  216,  217,
  153,  154,  154,   19,   20,   20,   20,   20,   20,   21,
   21,   35,   36,   37,   37,    9,   10,   11,   11,   66,
   67,   68,   68,    8,    8,    7,    7,   75,   76,  218,
   77,   69,   70,  219,   71,   72,   72,   72,   39,   39,
   39,   39,   39,   39,   39,   38,   38,  150,  150,  221,
  103,  222,  102,  223,  220,  220,   56,  145,  145,  145,
  146,  147,  148,  149,  139,  139,  139,  140,  141,  142,
    6,   99,   99,  100,  101,   98,   98,  143,  143,  144,
  144,   60,   61,   61,   62,   62,   23,   24,   24,   24,
   63,   63,   64,   65,  224,   26,   27,   27,   28,   28,
   25,   25,   29,   30,   30,   30,   31,   31,   22,  225,
   74,  226,   73,   52,   53,   53,   54,   49,   50,   50,
   51,  227,  228,  118,  229,  180,   40,   40,   40,  121,
  121,  121,   46,   46,   46,  230,   41,   43,   44,   42,
   45,   45,  119,  119,  119,  119,  120,  120,  181,  181,
  181,  181,  181,  231,  188,  182,  182,  189,  189,  232,
  191,  190,  233,  201,  203,  203,  202,  202,  202,  202,
  202,  202,  202,  202,  192,  192,  192,  192,  192,  192,
  192,  192,  192,  192,  192,  192,  192,  192,  192,  192,
  192,  193,  193,  193,  193,  193,  193,  193,  193,  193,
  193,  193,  193,  193,  193,  193,  193,  193,  193,  193,
  193,  193,  193,  193,  193,  193,  193,  193,  193,   86,
   86,   93,   87,   90,   91,  114,   78,   79,   80,   88,
   89,  115,  115,   85,   85,  116,  116,  117,  117,   94,
   95,   96,   97,   81,   82,   83,   84,  112,  113,  111,
  110,   92,   57,   58,   59,   59,  204,  204,    2,    3,
    3,    4,    4,    4,    4,    4,   16,   17,   17,   18,
   18,  186,  187,  122,  122,  122,  127,  127,  127,  129,
  128,  128,  131,  131,  130,  132,  133,  133,  133,  133,
  134,  236,  135,  137,  136,   55,  195,  197,  197,  197,
  197,  197,  197,  196,  196,   15,    1,   14,   13,   12,
  238,  238,  238,  238,  238,  237,  237,  178,  194,  175,
  176,  177,  234,  235,  152,  155,  155,  155,  155,  155,
  155,  155,  155,  155,  155,  155,  156,  156,  157,  184,
  185,  239,  240,  179,  151,  183,  183,  183,  183,  174,
  174,  174,  164,  165,  165,  165,  165,  165,  165,  172,
  172,  172,  172,  173,  173,  166,  198,  198,  167,  199,
  168,  241,  169,  170,  171,  158,  158,  158,  158,  159,
  159,  162,  162,  160,  161,  242,  163,  200,   32,   33,
   34,   47,   48,   48,
};
static const short socks_yylen[] = {                      2,
    0,    4,    3,    0,    2,    1,    1,    1,    1,    1,
    0,    2,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    3,    0,    4,    0,    4,    0,    6,    0,    6,    0,
    6,    0,    6,    1,    1,    2,    1,    1,    1,    1,
    1,    2,    1,    1,    1,    1,    1,    1,    0,    0,
    9,    0,    2,    3,    1,    1,    1,    1,    1,    1,
    2,    3,    1,    1,    2,    3,    1,    1,    2,    3,
    1,    1,    2,    1,    2,    1,    1,    4,    0,    0,
    4,    4,    0,    0,    4,    3,    3,    3,    1,    1,
    1,    1,    1,    1,    1,    0,    2,    4,    4,    0,
    4,    0,    4,    1,    1,    2,    3,    1,    1,    1,
    3,    3,    3,    1,    3,    3,    3,    3,    3,    3,
    3,    1,    1,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    1,    1,    1,    2,    3,    1,    1,    1,
    1,    1,    9,    7,    0,    7,    1,    1,    1,    1,
    1,    1,    3,    1,    1,    1,    1,    2,    3,    0,
    4,    0,    4,    3,    1,    2,    1,    3,    1,    2,
    1,    0,    0,    8,    0,    8,    1,    1,    1,    0,
    1,    1,    0,    1,    1,    0,    8,    4,    1,    7,
    0,    2,    1,    1,    1,    1,    0,    2,    1,    1,
    1,    1,    1,    0,    8,    0,    2,    1,    1,    0,
    4,    3,    0,    8,    0,    2,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    3,
    4,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    3,    1,    1,    2,    1,    1,    3,    1,
    2,    1,    1,    1,    1,    1,    3,    1,    2,    1,
    1,    2,    2,    3,    2,    2,    1,    1,    1,    1,
    1,    1,    3,    3,    3,    5,    1,    1,    1,    1,
    3,    0,    4,    3,    5,    3,    3,    1,    1,    1,
    1,    1,    1,    1,    2,    3,    3,    3,    3,    3,
    1,    1,    1,    1,    1,    1,    2,    4,    3,    3,
    3,    3,    3,    3,    3,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    2,    1,    0,    2,    3,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    1,    1,    2,    3,    1,    3,    1,    3,    1,    2,
    2,    1,    1,    2,    2,    1,    1,    1,    1,    1,
    1,    1,    1,    1,    1,    0,    3,    3,    2,    0,
    3,    1,    1,    3,    1,    1,    1,    1,    5,    1,
    1,    1,    1,    2,
};
static const short socks_yydefred[] = {                   0,
    1,    0,    0,    0,    0,    0,    0,   68,    0,    0,
    0,    0,    0,    0,    0,    0,  110,  109,  114,   72,
    0,  113,  112,  115,   65,   66,   64,   67,  111,    0,
    0,   46,   48,    0,    0,    0,    0,   99,  103,  171,
  172,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   17,   16,   33,   34,    0,   40,
   35,   13,   14,   15,  161,  162,   19,   20,   21,   22,
   25,   24,   27,   28,   30,   31,  142,  143,   32,   18,
   29,   23,    0,    4,   36,   37,   38,   39,  128,  129,
  130,   26,    0,    0,    0,  120,  122,    0,    0,    0,
    0,    0,    0,    0,    0,  117,    0,    0,    0,    0,
    0,  104,  100,    0,    0,    0,  182,  180,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   12,    0,  139,  140,  141,    0,    0,  135,  136,  137,
  138,  159,  160,  158,  157,    0,    0,   69,   73,  153,
  154,    0,  152,    0,    0,    0,    0,   91,    0,   90,
    0,    0,  107,  106,  108,    0,    0,    0,    0,  127,
  179,  174,  175,  176,    0,  173,  134,  131,  132,  133,
  144,  145,  146,  147,  148,  149,  150,  151,  165,  195,
  224,  233,  192,    9,    5,   10,    6,    7,    8,  124,
  121,    0,  123,  119,  118,    0,  156,    0,    0,   54,
    0,    0,   93,   96,   97,    0,  105,  101,  436,  439,
  441,  443,  444,   98,  420,    0,    0,    0,  421,  422,
    0,  416,  417,  418,  419,  102,  187,  183,    0,  191,
  181,    0,  178,    0,    0,    0,    0,    0,  126,   70,
    0,    0,    0,    0,   95,    0,    0,    0,    0,  423,
  186,  190,  168,  167,    0,  327,  328,    0,    0,    0,
  193,    0,    0,    0,    0,    0,    0,   47,   49,  437,
  438,  424,  440,  426,  442,  428,  455,  458,    0,  449,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  397,  403,  402,  401,
  400,  404,  406,  398,  399,    0,    0,  396,  462,    0,
  164,    0,    0,   42,   44,  457,  453,  447,  452,    0,
  448,  170,  169,  166,   50,   52,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  249,  250,  251,  252,  257,  220,
  259,  261,  246,  247,  245,  221,  258,  352,  222,  347,
  351,  348,  349,  357,  358,  359,  360,  260,  219,    0,
    0,  253,  229,  228,  223,  255,  256,  254,  248,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  237,  238,  241,  242,  244,  267,  268,  269,  262,  263,
  265,  264,  266,  273,  274,  282,  283,  271,  272,  281,
  275,  276,  277,  279,  278,  288,  285,  286,  287,  289,
  284,  270,  280,  350,  243,  239,  240,    0,    0,  201,
  202,  214,  216,  213,  197,  198,  199,    0,    0,    0,
  215,    0,    0,    0,    0,    0,    0,    0,    0,  412,
  405,    0,  408,  410,    0,    0,    0,  464,    0,   63,
   41,    0,    0,    0,  456,  454,    0,    0,  230,    0,
    0,    0,    0,  414,    0,    0,    0,  413,    0,  346,
    0,    0,    0,    0,    0,  362,    0,    0,    0,    0,
    0,  227,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  236,    0,  218,    0,
    0,  206,    0,  324,    0,  323,  409,  332,  333,  334,
  335,  336,  329,    0,  381,  382,  383,  384,  385,  380,
    0,  379,  378,  340,  341,  337,    0,   75,   76,   77,
   78,   79,    0,   74,    0,  411,  342,    0,    0,  415,
    0,    0,  163,   62,   57,   58,   59,   60,   43,    0,
   45,    0,    0,    0,  232,  184,  188,  366,    0,  389,
  376,  344,    0,  353,  354,  355,    0,  361,    0,  364,
    0,  368,  369,  370,  371,  372,  373,  367,    0,   83,
   84,    0,   87,   88,    0,    0,  343,    0,    0,  377,
  314,  315,  316,  317,  297,  298,  299,  294,  295,  300,
  301,  290,    0,  293,  304,  305,  292,  310,  311,  312,
  313,  320,  318,  319,  322,  321,  302,  303,  306,  307,
  308,  309,  296,  460,    0,    0,    0,    0,    0,    0,
  326,  331,  387,  339,   81,  393,    0,  390,    0,    0,
   56,    0,    0,  231,    0,    0,  388,  394,    0,  363,
    0,  375,   85,   89,  196,  391,  225,  291,    0,  234,
  194,  209,  208,  205,  204,    0,    0,  392,  445,    0,
    0,  432,  433,  395,   71,    0,    0,    0,  434,  435,
  356,  365,  461,  459,    0,    0,  430,  431,   51,   53,
    0,    0,    0,  451,    0,    0,  210,  207,  212,
};
static const short socks_yydgoto[] = {                    3,
  421,  307,  573,  574,   17,   18,  216,  217,  355,  644,
  645,  356,  357,  358,  359,  360,  586,  587,  312,  593,
  594,   57,   19,  145,   59,  361,  265,  334,   61,  175,
  176,  425,  685,  744,  362,  641,  642,   20,   21,  464,
  465,  466,  467,  723,  757,  726,  320,  321,  363,  241,
  242,  364,  238,  239,  365,   62,  366,  565,  566,   63,
  152,  153,   64,   65,   66,  315,  159,  160,   68,  116,
   69,   70,   71,   72,   73,  115,   74,  426,  427,  428,
  429,  430,  431,  432,  433,  434,  435,  436,  437,  438,
  439,  440,  441,  442,  443,  444,  445,   75,   76,   77,
   78,   22,   23,   81,   82,  278,  211,  491,  492,  446,
  447,  448,  449,  450,  451,  452,  453,  194,  468,  469,
  470,  367,   83,   84,  195,  132,  368,  369,  455,  370,
  371,  372,  373,  374,  375,  376,  377,  378,   25,   26,
   27,   28,   86,   87,   88,   89,   90,   91,  178,   29,
  601,  602,  149,  105,  316,  317,  318,  260,  739,  290,
  327,  328,  329,  224,  225,  226,  227,  228,  229,  230,
  733,  734,  707,  231,  485,  524,  597,  379,  505,  197,
  380,  381,  236,  486,  598,  487,  526,  198,  382,  383,
  384,  385,  457,  386,  387,  638,  639,  282,  284,  292,
  199,  458,  459,  268,  388,  389,    4,  609,  493,  494,
  109,  110,  497,  498,  610,  206,  272,  162,  161,  201,
  136,  137,  202,  244,  169,  168,  248,  297,  245,  689,
  246,  614,  247,  481,  510,  629,  580,  581,  482,  511,
  286,  496,
};
static const short socks_yysindex[] = {                -289,
    0, 1789,    0, -208,   -8,   20,   29,    0,   34,   56,
   86,  108,  142,  172,  178, -173,    0,    0,    0,    0,
 1789,    0,    0,    0,    0,    0,    0,    0,    0,  200,
  215,    0,    0,  205,  216,  234,  243,    0,    0,    0,
    0,  267,  272,  285,  289,  298,  312,  316,  318,  319,
  320,  322,  323,  327,    0,    0,    0,    0,   46,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -208,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   30,   31,   35,    0,    0,   38,   39,   41,
   57, -252,  334,  336,   43,    0, -179,  -77,  352,  359,
  123,    0,    0, -213,  365,  369,    0,    0,   70,   99,
 -148,   87,   87,   87,  122,  124, -261, -235, -225,  390,
    0, -160,    0,    0,    0,  153,  153,    0,    0,    0,
    0,    0,    0,    0,    0,   82,   83,    0,    0,    0,
    0, -179,    0,  396,  397,  134,  134,    0,  123,    0,
 -132, -132,    0,    0,    0, -177, -154,  131,  135,    0,
    0,    0,    0,    0, -148,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  153,    0,    0,    0,  329,    0,  128,  130,    0,
  413,  417,    0,    0,    0, -132,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  424,  426,  427,    0,    0,
  118,    0,    0,    0,    0,    0,    0,    0,  131,    0,
    0,  135,    0, -211, -219, -219, -219,  354,    0,    0,
  425,  430,  -54,  -54,    0, -249,  126,  127,  -51,    0,
    0,    0,    0,    0,  431,    0,    0,  367,  368,  370,
    0, 2186,  136,  158,  437,  438,  439,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -322,    0,
  453, -322, -243, 3992, 3992, 4092, -229,  441,  442,  443,
  444,  445,  446,  447,  448,  137,    0,    0,    0,    0,
    0,    0,    0,    0,    0, 2186,  138,    0,    0,  136,
    0,  462,  218,    0,    0,    0,    0,    0,    0,  159,
    0,    0,    0,    0,    0,    0,  458,  460,  461,  463,
  465,  149,  470,  471, -114,  475,  482,  483,   90,  484,
  485,  488,  490,  491,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 3992,
  138,    0,    0,    0,    0,    0,    0,    0,    0,  138,
  495,  496,  499,  500,  509,  510,  514,  515,  516,  517,
  518,  519,  520,  521,  522,  527,  529,  530,  531,  533,
  534,  535,  536,  537,  538,  541,  542,  543,  547,  551,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0, 4092,  138,    0,
    0,    0,    0,    0,    0,    0,    0, -229,  138,  -12,
    0,  341,  131, -149, -153,  231,  236, -176, -260,    0,
    0,  560,    0,    0,  248,  562,  268,    0,  264,    0,
    0,  218, -102, -102,    0,    0,  577,  581,    0,  270,
  131,  135,  271,    0,  572,  195,  183,    0,  265,    0,
  579, -158,  277,  280,  174,    0,  282,  283, -290,  300,
  357,    0, 3992,  248,  601, 3992,  303,  240,  241,  247,
  249,  284,  286,  288,  252,  253,  325,  332,  -25,  333,
 -139,  290,  257,  266,  273,  275,  287,  293,  294,  281,
  295, -137, -124, -122,  292,  342,    0, 4092,    0, -229,
  653,    0,  668,    0,  341,    0,    0,    0,    0,    0,
    0,    0,    0, -149,    0,    0,    0,    0,    0,    0,
 -153,    0,    0,    0,    0,    0, -176,    0,    0,    0,
    0,    0, -260,    0, -177,    0,    0,  673, -177,    0,
  674, 2186,    0,    0,    0,    0,    0,    0,    0, -102,
    0,  134,  134, -177,    0,    0,    0,    0, -141,    0,
    0,    0, -177,    0,    0,    0,  689,    0,  435,    0,
  691,    0,    0,    0,    0,    0,    0,    0, -290,    0,
    0,  300,    0,    0,  357,  618,    0, -177,  619,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  387,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  701,  624,  626,  489,  -96,  394,
    0,    0,    0,    0,    0,    0, -177,    0, -207,  632,
    0,  714,  715,    0,  414,  414,    0,    0,  412,    0,
  418,    0,    0,    0,    0,    0,    0,    0,  419,    0,
    0,    0,    0,    0,    0,  717,  731,    0,    0,  414,
  414,    0,    0,    0,    0,  -54,  -54,  343,    0,    0,
    0,    0,    0,    0,  421,  423,    0,    0,    0,    0,
 -322,  432,  434,    0,  433,  436,    0,    0,    0,
};
static const short socks_yyrindex[] = {                   0,
    0,   11,    0,    5,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   11,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    5,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  782,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  788,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 1876,    0,    0,    0,    0,    0,    0, 1697,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, 1971,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 2064,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, 2175,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   12,  254,  457,    0,    0,
  672,    0,    0,    0,    0,    0,    0,    0,  875,    0,
    0, 1083,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  420,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  422,  422,  428, -202,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0, -104,    0,    0,    0, 2263,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -92,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  -91,    0,    0,
    0,    0,    0,    0,    0,    0,    0, -103,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, 1286,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, 2913,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  670,    0,    0,  670,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  671,    0, -100,
    0,    0,    0,    0, 3780,    0,    0,    0,    0,    0,
    0,    0,    0, 2566,    0,    0,    0,    0,    0,    0,
 2740,    0,    0,    0,    0,    0, 2363,    0,    0,    0,
    0,    0, 3087,    0,    0,    0,    0,    0,    0,    0,
    0,  676,    0,    0,    0,    0,    0,    0,    0, 1494,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, 3260,    0,
    0, 3433,    0,    0, 3606,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  735,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, 3809, 3809,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, 3837,
 3837,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -108,    0,    0,    0,    0,    0,    0,
};
static const short socks_yygindex[] = {                   0,
    0, -267,  225,    0,   -3,   36,    0,  -78,    0,  157,
    0, -264, -262, -257,    0, -254,  217,    0, -277,    0,
  210,    0,   40,    0,    0,   -4,    0,    0,    0,    0,
  633,    0,    0,    0,    0,  170,    0,  792,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  501,    0, -216,
    0,    0, -175,    0,    0,    0, -256,    0,  250,    0,
    0,  667,    0,    0,    0,   47,    0,  663,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   49,   62,    0,    0, -250, -151,  331,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0, -433,
    0,    0,    0,  741,    0,    0, -259,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   37,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  235,   77,
    0,    0,  693,    0,    0, -302,    0,    0, -613,    0,
  567, -279,    0, -532, -574,  664,  665,    0, -165, -164,
    0,    0,    0, -543,    0,    0,  306,    0,    0,    0,
    0, -286,    0,  449,    0, -343,    0,    0, -273,  204,
    0, -247,    0,    0,    0,  198,    0,    0,    0,   96,
    0,    0, -430,  121,    0,    0,    0, -467,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -89,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  493,  335,    0,  259,    0,    0,    0,
    0,    0,
};
#define YYTABLESIZE 4562
static const short socks_yytable[] = {                   60,
   55,  234,  235,  279,   11,  212,  289,  308,  390,  309,
  116,  425,  331,  483,  310,  314,  211,  311,  424,  663,
  407,  217,    8,  471,  217,  262,  611,  557,  422,  462,
  460,  461,  226,  235,  559,  287,  454,  523,   24,   56,
   85,  423,  463,   58,  705,    1,    2,  203,  456,   93,
   67,  308,   79,  309,  200,  200,  200,   24,  310,  314,
  332,  311,  696,  261,   30,   80,  698,    5,    6,   31,
  704,  337,  338,    7,    8,    9,   10,   94,   60,   55,
   92,   32,   33,  218,   34,  163,   95,   35,   36,   37,
  708,   96,  740,  522,  150,  151,   38,   39,   40,   41,
   11,   12,   13,   14,  716,  164,   42,   43,  280,  190,
  191,  192,  249,   97,  333,  558,  747,  748,   56,   85,
   44,   45,   58,   15,  730,  560,  687,  686,  326,   67,
  263,   79,  281,  300,   46,  516,  425,  255,  165,   47,
   48,   49,  701,   98,   80,   16,  264,  515,  211,  211,
  211,  211,  211,  200,  200,  200,  200,  200,  200,   92,
  605,  606,  607,  608,  728,   99,  193,  217,  632,  633,
  634,  635,  636,  637,  219,  220,  221,  222,  223,  729,
  424,  103,  104,  588,  589,  590,  591,  142,  143,  144,
  422,  148,  211,  211,  471,  172,  173,  174,  454,  100,
  462,  154,  155,  423,  219,  220,  221,  222,  223,  304,
  456,  183,  184,  463,  568,  569,  570,  571,  572,  575,
  576,  577,  578,  579,   50,   51,   52,  219,  220,  101,
  222,  223,  275,  276,  277,  102,  646,  185,  186,  649,
  219,  220,  221,  222,  561,  562,  563,  187,  188,  214,
  215,  266,  267,  427,  211,  480,  508,  107,   53,   54,
  108,  211,  111,  584,  585,  407,  217,  313,  425,  425,
  425,  425,  425,  112,   11,   11,   11,  226,  235,  425,
  424,  425,  425,  425,  425,  617,  471,  425,  425,  425,
  422,  113,  462,  425,  425,  425,  425,  567,  454,  700,
  114,  425,  425,  423,  425,  463,  287,  425,  425,  425,
  456,  313,  425,  425,  624,  625,  425,  425,  425,  425,
  425,  425,  425,  425,  117,  616,  425,  425,  425,  118,
  211,   11,  662,  665,  666,  677,  678,  308,  425,  309,
  425,  425,  119,  425,  310,  314,  120,  311,  679,  680,
  681,  682,  724,  725,  425,  121,   11,  179,  180,  425,
  425,  425,  116,  425,  425,  425,  269,  270,  425,  122,
  425,  425,  425,  123,  425,  124,  125,  126,  427,  127,
  128,  425,  425,  425,  129,  288,  130,  133,  134,  425,
  425,  146,  135,  147,  148,  138,  139,  156,  140,  425,
  425,  425,  425,  425,  157,  425,  425,  425,  425,  425,
  425,  425,  425,  425,  141,  425,  158,  425,  425,  425,
  425,  425,  166,  425,  425,  425,  167,  170,  425,  171,
  425,  425,  425,  177,  181,  189,  182,  425,  200,  204,
  205,  208,  209,  425,  425,  425,  425,  210,  237,  425,
  425,  250,  240,  706,  425,  251,  429,  252,  253,  425,
  702,  703,  254,  425,  425,  425,  425,  425,  425,  425,
  256,  754,  257,  258,  259,  592,  271,  425,  425,  425,
  425,  425,  273,  283,  285,  749,  750,  274,  293,  294,
  295,  322,  296,  319,  323,  324,  325,  330,  472,  473,
  474,  475,  476,  477,  478,  479,  480,  484,  489,  490,
  427,  427,  427,  427,  427,  499,  495,  500,  501,  504,
  502,  427,  503,  427,  427,  427,  427,  506,  507,  427,
  427,  427,  512,  731,  732,  427,  427,  427,  427,  513,
  514,  517,  518,  427,  427,  519,  427,  520,  521,  427,
  427,  427,  527,  528,  427,  427,  529,  530,  427,  427,
  427,  427,  427,  427,  427,  427,  531,  532,  427,  427,
  427,  533,  534,  535,  536,  537,  538,  539,  540,  541,
  427,  429,  427,  427,  542,  427,  543,  544,  545,  592,
  546,  547,  548,  549,  550,  551,  427,  313,  552,  553,
  554,  427,  427,  427,  555,  427,  427,  427,  556,  564,
  427,  582,  427,  427,  427,  583,  427,  595,  596,  599,
  600,  603,  612,  427,  427,  427,  613,  615,  618,  619,
  620,  427,  427,  621,  626,  508,  623,  627,  628,  630,
  631,  427,  427,  427,  427,  427,  640,  427,  427,  427,
  427,  427,  427,  427,  427,  427,  643,  427,  648,  427,
  427,  427,  427,  427,  650,  427,  427,  427,  651,  652,
  427,  446,  427,  427,  427,  653,  655,  654,  656,  427,
  657,  658,  660,  659,  668,  427,  427,  427,  427,  661,
  664,  427,  427,  669,  667,  675,  427,  672,  688,  684,
  670,  427,  671,  673,  674,  427,  427,  427,  427,  427,
  427,  427,  676,  429,  429,  429,  429,  429,  683,  427,
  427,  427,  427,  427,  429,  690,  429,  429,  429,  429,
  697,  699,  429,  429,  429,  709,  338,  711,  429,  429,
  429,  429,  715,  717,  718,  719,  429,  429,  720,  429,
  721,  727,  429,  429,  429,  722,  735,  429,  429,  736,
  737,  429,  429,  429,  429,  429,  429,  429,  429,  741,
  738,  429,  429,  429,  745,  742,  743,  746,  752,  288,
  753,    3,  755,  429,  756,  429,  429,    2,  429,  407,
  758,  226,  203,  759,  226,  235,  446,  235,  692,  429,
  407,  714,  695,  694,  429,  429,  429,  243,  429,  429,
  429,  713,  106,  429,  691,  429,  429,  429,  207,  429,
  488,  213,  604,  131,  196,  291,  429,  429,  429,  647,
  232,  233,  710,  751,  429,  429,  712,  509,  525,  693,
    0,    0,    0,  622,  429,  429,  429,  429,  429,    0,
  429,  429,  429,  429,  429,  429,  429,  429,  429,    0,
  429,    0,  429,  429,  429,  429,  429,    0,  429,  429,
  429,    0,    0,  429,  185,  429,  429,  429,    0,    0,
    0,    0,  429,    0,    0,    0,    0,    0,  429,  429,
  429,  429,    0,    0,  429,  429,    0,    0,    0,  429,
    0,    0,    0,    0,  429,    0,    0,    0,  429,  429,
  429,  429,  429,  429,  429,    0,    0,    0,    0,    0,
    0,    0,  429,  429,  429,  429,  429,    0,  446,  446,
  446,  446,  446,    0,    0,    0,    0,    0,    0,  446,
    0,  446,  446,  446,  446,    0,    0,  446,  446,  446,
    0,    0,    0,  446,  446,  446,  446,    0,    0,    0,
    0,  446,  446,    0,  446,    0,    0,  446,  446,  446,
    0,    0,  446,  446,    0,    0,  446,  446,  446,  446,
  446,  446,  446,  446,    0,    0,  446,  446,  446,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  446,  185,
  446,  446,    0,  446,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  446,    0,    0,    0,    0,  446,
  446,  446,    0,  446,  446,  446,    0,    0,    0,    0,
  446,  446,  446,    0,  446,    0,    0,    0,    0,    0,
    0,  446,  446,  446,    0,    0,    0,    0,    0,  446,
  446,    0,    0,    0,    0,    0,    0,    0,    0,  446,
  446,  446,  446,  446,    0,  446,  446,  446,  446,  446,
  446,  446,  446,  446,    0,  446,    0,  446,  446,  446,
  446,  446,  189,  446,  446,  446,    0,    0,  446,    0,
  446,  446,  446,    0,    0,    0,    0,  446,    0,    0,
    0,    0,    0,  446,  446,  446,  446,    0,    0,  446,
  446,    0,    0,    0,  446,    0,    0,    0,    0,  446,
    0,    0,    0,  446,  446,  446,  446,  446,  446,  446,
    0,    0,    0,    0,    0,    0,    0,  446,  446,  446,
  446,  446,  185,    0,  185,  185,  185,  185,    0,    0,
  185,  185,  185,    0,    0,    0,  185,  185,  185,  185,
    0,    0,    0,    0,  185,  185,    0,  185,    0,    0,
  185,  185,  185,    0,    0,  185,  185,    0,    0,  185,
  185,  185,  185,  185,  185,  185,  185,    0,    0,  185,
  185,  185,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  185,    0,  185,  185,    0,  185,  189,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  185,    0,    0,
    0,    0,  185,  185,  185,    0,  185,    0,  185,    0,
    0,    0,    0,  185,  185,  185,    0,  185,    0,    0,
    0,    0,    0,    0,  185,    0,  185,    0,    0,    0,
    0,    0,  185,  185,    0,    0,    0,    0,    0,    0,
    0,    0,  185,  185,  185,  185,  185,    0,  185,  185,
  185,  185,  185,  185,  185,  185,  185,    0,  185,    0,
  185,  185,  185,  185,  185,   61,  185,  185,  185,    0,
    0,  185,    0,  185,  185,  185,    0,    0,    0,    0,
  185,    0,    0,    0,    0,    0,  185,  185,  185,  185,
    0,    0,  185,  185,    0,    0,    0,  185,    0,    0,
    0,    0,  185,    0,    0,    0,  185,  185,  185,  185,
  185,  185,  185,    0,    0,    0,    0,    0,    0,    0,
  185,  185,  185,  185,  185,    0,    0,    0,    0,    0,
  189,    0,  189,  189,  189,  189,    0,    0,  189,  189,
  189,    0,    0,    0,  189,  189,  189,  189,    0,    0,
    0,    0,  189,  189,    0,  189,    0,    0,  189,  189,
  189,    0,    0,  189,  189,    0,    0,  189,  189,  189,
  189,  189,  189,  189,  189,    0,    0,  189,  189,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  189,
   61,  189,  189,    0,  189,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  189,    0,    0,    0,    0,
  189,  189,  189,    0,  189,    0,  189,    0,    0,    0,
    0,  189,  189,  189,    0,  189,    0,    0,    0,    0,
    0,    0,  189,    0,  189,    0,    0,    0,    0,    0,
  189,  189,    0,    0,    0,    0,    0,    0,    0,    0,
  189,  189,  189,  189,  189,    0,  189,  189,  189,  189,
  189,  189,  189,  189,  189,    0,  189,    0,  189,  189,
  189,  189,  189,   55,  189,  189,  189,    0,    0,  189,
    0,  189,  189,  189,    0,    0,    0,    0,  189,    0,
    0,    0,    0,    0,  189,  189,  189,  189,    0,    0,
  189,  189,    0,    0,    0,  189,    0,    0,    0,    0,
  189,    0,    0,    0,  189,  189,  189,  189,  189,  189,
  189,    0,    0,    0,    0,    0,    0,    0,  189,  189,
  189,  189,  189,   61,    0,   61,   61,   61,   61,    0,
    0,   61,   61,   61,    0,    0,    0,   61,   61,   61,
   61,    0,    0,    0,    0,   61,   61,    0,   61,    0,
    0,   61,   61,   61,    0,    0,   61,   61,    0,    0,
   61,   61,   61,   61,   61,   61,   61,   61,    0,    0,
   61,   61,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   61,    0,   61,   61,    0,   61,   55,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   61,    0,
    0,    0,    0,   61,   61,   61,    0,   61,    0,   61,
    0,    0,    0,    0,   61,   61,   61,    0,   61,    0,
    0,    0,    0,    0,    0,   61,    0,   61,    0,    0,
    0,    0,    0,   61,   61,    0,    0,    0,    0,    0,
    0,    0,    0,   61,   61,   61,   61,   61,    0,   61,
   61,   61,   61,   61,   61,   61,   61,   61,    0,   61,
    0,   61,   61,   61,   61,   61,   92,   61,   61,   61,
    0,    0,   61,    0,   61,   61,   61,    0,    0,    0,
    0,   61,    0,    0,    0,    0,    0,   61,   61,   61,
   61,    0,    0,   61,   61,    0,    0,    0,   61,    0,
    0,    0,    0,   61,    0,    0,    0,   61,   61,   61,
   61,   61,   61,   61,    0,    0,    0,    0,    0,    0,
    0,   61,   61,   61,   61,   61,    0,    0,    0,    0,
    0,   55,    0,   55,   55,   55,   55,    0,    0,   55,
   55,   55,    0,    0,    0,   55,   55,   55,   55,    0,
    0,    0,    0,   55,   55,    0,   55,    0,    0,   55,
   55,   55,    0,    0,   55,   55,    0,    0,   55,   55,
   55,   55,   55,   55,   55,   55,    0,    0,   55,   55,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   55,   92,   55,   55,    0,   55,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   55,    0,    0,    0,
    0,   55,   55,   55,    0,   55,    0,   55,    0,    0,
    0,    0,   55,   55,   55,    0,   55,    0,    0,    0,
    0,    0,    0,   55,    0,   55,    0,    0,    0,    0,
    0,   55,   55,    0,    0,  155,    0,    0,    0,    0,
    0,   55,   55,   55,   55,   55,    0,   55,   55,   55,
   55,   55,   55,   55,   55,   55,    0,   55,    0,   55,
   55,   55,   55,   55,    0,   55,   55,   55,    0,    0,
   55,    0,   55,   55,   55,    0,    0,    0,    0,   55,
    0,    0,    0,    0,    0,   55,   55,   55,   55,    0,
    0,   55,   55,    0,    0,    0,   55,    0,    0,    0,
    0,   55,    0,    0,    0,   55,   55,   55,   55,   55,
   55,   55,    0,    0,    0,    0,    0,    0,    0,   55,
   55,   55,   55,   55,   92,    0,   92,   92,   92,   92,
  177,    0,   92,   92,   92,    0,    0,    0,   92,   92,
   92,   92,    0,    0,    0,    0,   92,   92,    0,   92,
    0,    0,   92,   92,   92,    0,    0,    0,    0,    0,
    0,   92,   92,   92,   92,   92,   92,   92,   92,    0,
    0,   92,   92,   92,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   92,    0,   92,   92,    0,   92,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   92,
    0,    0,    0,    0,   92,   92,   92,    0,   92,    0,
   92,    0,    0,    0,    0,    0,    0,    0,    0,   92,
    0,    0,    0,  125,    5,    6,   92,    0,   92,    0,
    7,    8,    9,   10,   92,   92,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   11,   12,   13,
   14,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   15,    0,    0,    0,    0,    0,    0,    0,    0,   92,
   92,   92,    0,    0,    0,   92,    0,    0,    0,   92,
    0,    0,   16,    0,   92,  155,  155,  155,  155,    0,
    0,  155,  155,  155,    0,    0,    0,  155,  155,  155,
  155,    0,    0,   92,   92,  155,  155,    0,  155,    0,
    0,  155,  155,  155,   94,    0,    0,    0,    0,    0,
  155,  155,  155,  155,  155,  155,  155,  155,    0,    0,
  155,  155,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  155,    0,  155,  155,    0,  155,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  155,    0,
    0,    0,    0,  155,  155,  155,    0,  155,    0,  155,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  177,  177,  177,  177,    0,    0,  177,  177,  177,    0,
    0,    0,  177,  177,  177,  177,    0,    0,    0,    0,
  177,  177,  463,  177,    0,    0,  177,  177,  177,    0,
    0,    0,    0,    0,    0,  177,  177,  177,  177,  177,
  177,  177,  177,    0,    0,  177,  177,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  177,    0,  177,
  177,    0,  177,    0,    0,    0,    0,    0,  155,  155,
  155,    0,    0,  177,    0,    0,    0,    0,  177,  177,
  177,    0,  177,    0,  177,    0,    0,    0,    0,    0,
    0,    0,    0,  125,  125,  125,  125,    0,    0,  125,
  125,  125,  155,  155,    0,  125,  125,  125,  125,    0,
    0,    0,    0,  125,  125,    0,  125,    0,    0,  125,
  125,  125,    0,    0,    0,    0,    0,    0,  125,  125,
  125,  125,  125,  125,  125,  125,    0,    0,  125,  125,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  125,    0,  125,  125,    0,  125,    0,    0,    0,    0,
    0,    0,    0,  177,  177,  177,  125,    0,    0,    0,
    0,  125,  125,  125,    0,  125,    0,  125,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  177,  177,    0,
    0,    0,    0,    0,   94,   94,   94,   94,    0,    0,
   94,   94,   94,  298,    0,    0,   94,   94,   94,   94,
    0,    0,    0,    0,   94,   94,    0,   94,    0,    0,
   94,   94,   94,    0,    0,    0,    0,    0,   34,   94,
   94,   94,   94,   94,   94,   94,   94,  338,    0,   94,
   94,    0,   40,   41,    0,    0,  125,  125,  125,    0,
    0,   94,  299,   94,   94,    0,   94,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   94,    0,    0,
    0,    0,   94,   94,   94,    0,   94,    0,   94,    0,
  125,  125,  463,  463,  463,  463,    0,    0,  463,  463,
  463,    0,    0,    0,  463,  463,  463,  463,  300,    0,
    0,    0,  463,  463,    0,  463,    0,  301,  463,  463,
  463,    0,    0,  302,  303,    0,    0,  463,  463,  463,
  463,  463,  463,  463,  463,    0,    0,  463,  463,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  463,
    0,  463,  463,    0,  463,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  463,    0,   94,   94,   94,
  463,  463,  463,    0,  463,    0,  463,    0,    0,  338,
  338,  338,  338,  338,  304,    0,    0,    0,  305,    0,
  338,    0,    0,  306,    0,    0,    0,    0,  338,  338,
    0,   94,   94,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  338,  338,    0,  338,    0,    0,    0,    0,
    0,    0,    0,  338,  338,    0,    0,    0,    0,  338,
  338,  338,  338,  338,  338,    0,    0,  338,  338,  338,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  330,    0,    0,    0,    0,  463,  463,  463,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  338,  338,  338,    0,  338,    0,    0,    0,  463,
  463,    0,  338,    0,  338,    0,    0,    0,    0,    0,
  338,  338,    0,    0,    0,    0,    0,    0,    0,    0,
  338,  338,  338,  338,  338,    0,  338,  338,  338,  338,
  338,  338,  338,  338,  338,    0,  338,    0,  338,  338,
  338,  338,  338,    0,  338,  338,  338,    0,    0,  338,
    0,  338,  338,  338,    0,    0,    0,    0,  338,    0,
    0,    0,    0,    0,  338,    0,    0,    0,    0,    0,
  338,  338,    0,    0,    0,  338,    0,    0,    0,    0,
  338,    0,    0,    0,  338,  338,  338,  338,  338,  338,
  338,    0,  330,  330,  330,  330,  330,    0,  338,    0,
    0,  338,  338,  330,    0,    0,    0,    0,    0,    0,
    0,  330,  330,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  330,  330,    0,  330,    0,
    0,    0,    0,    0,  386,    0,  330,  330,    0,    0,
    0,    0,  330,  330,  330,  330,  330,  330,    0,    0,
  330,  330,  330,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  330,    0,  330,    0,  330,    0,
    0,    0,    0,    0,    0,  330,    0,  330,    0,    0,
    0,    0,    0,  330,  330,    0,    0,    0,    0,    0,
    0,    0,    0,  330,  330,  330,  330,  330,    0,  330,
  330,  330,  330,  330,  330,  330,  330,  330,    0,  330,
    0,  330,  330,  330,  330,  330,    0,  330,  330,  330,
    0,    0,  330,    0,  330,  330,  330,    0,    0,    0,
    0,  330,    0,    0,    0,    0,    0,  330,    0,    0,
    0,    0,    0,  330,  330,    0,    0,  386,  330,    0,
    0,    0,    0,  330,    0,  386,  386,    0,  330,  330,
  330,  330,  330,  330,    0,    0,    0,    0,    0,  386,
  386,  330,  386,    0,  330,  330,    0,  345,    0,    0,
  386,  386,    0,    0,    0,    0,  386,  386,  386,  386,
  386,  386,    0,    0,  386,  386,  386,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  386,  386,
  386,    0,  386,    0,    0,    0,    0,    0,    0,  386,
    0,  386,    0,    0,    0,    0,    0,  386,  386,    0,
    0,    0,    0,    0,    0,    0,    0,  386,  386,  386,
  386,  386,    0,  386,  386,  386,  386,  386,  386,  386,
  386,  386,    0,  386,    0,  386,  386,  386,  386,  386,
    0,  386,  386,  386,    0,    0,  386,    0,  386,  386,
  386,    0,    0,    0,    0,  386,    0,    0,    0,    0,
    0,  386,    0,    0,    0,    0,    0,  386,  386,    0,
  345,    0,  386,    0,    0,    0,    0,  386,  345,  345,
    0,  386,  386,  386,  386,  386,  386,  386,    0,    0,
    0,    0,  345,  345,    0,  386,    0,    0,  386,  386,
    0,   80,    0,  345,  345,    0,    0,    0,    0,  345,
  345,  345,  345,  345,  345,    0,    0,  345,  345,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  345,  345,  345,    0,  345,    0,    0,    0,    0,
    0,    0,  345,    0,  345,    0,    0,    0,    0,    0,
  345,  345,    0,    0,    0,    0,    0,    0,    0,    0,
  345,  345,  345,  345,  345,    0,  345,  345,  345,  345,
  345,  345,  345,  345,  345,    0,  345,    0,  345,  345,
  345,  345,  345,    0,  345,  345,  345,    0,    0,  345,
    0,  345,  345,  345,    0,    0,    0,    0,  345,    0,
    0,    0,    0,    0,  345,    0,    0,    0,    0,    0,
  345,  345,    0,    0,   80,  345,    0,    0,    0,    0,
  345,    0,   80,   80,  345,  345,  345,  345,  345,  345,
  345,    0,    0,    0,    0,    0,   80,   80,  345,   80,
    0,  345,  345,    0,  374,    0,    0,   80,   80,    0,
    0,    0,    0,   80,   80,   80,   80,   80,   80,    0,
    0,   80,   80,   80,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   80,    0,   80,    0,   80,
    0,    0,    0,    0,    0,    0,   80,    0,   80,    0,
    0,    0,    0,    0,   80,   80,    0,    0,    0,    0,
    0,    0,    0,    0,   80,   80,   80,   80,   80,    0,
   80,   80,   80,   80,   80,   80,   80,   80,   80,    0,
   80,    0,   80,   80,   80,   80,   80,    0,   80,   80,
   80,    0,    0,   80,    0,   80,   80,   80,    0,    0,
    0,    0,   80,    0,    0,    0,    0,    0,   80,    0,
    0,    0,    0,    0,   80,   80,    0,  374,    0,   80,
    0,    0,    0,    0,   80,  374,  374,    0,    0,   80,
   80,   80,   80,   80,   80,    0,    0,    0,    0,  374,
  374,    0,   80,    0,    0,   80,   80,   82,    0,    0,
  374,  374,    0,    0,    0,    0,  374,  374,  374,  374,
  374,  374,    0,    0,  374,  374,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  374,  374,
  374,    0,  374,    0,    0,    0,    0,    0,    0,  374,
    0,  374,    0,    0,    0,    0,    0,  374,  374,    0,
    0,    0,    0,    0,    0,    0,    0,  374,  374,  374,
  374,  374,    0,  374,  374,  374,  374,  374,  374,  374,
  374,  374,    0,  374,    0,  374,  374,  374,  374,  374,
    0,  374,  374,  374,    0,    0,  374,    0,  374,  374,
  374,    0,    0,    0,    0,  374,    0,    0,    0,    0,
    0,  374,    0,    0,    0,    0,    0,  374,  374,    0,
   82,    0,  374,    0,    0,    0,    0,  374,   82,   82,
    0,  374,  374,  374,  374,  374,  374,  374,    0,    0,
    0,    0,   82,   82,    0,  374,    0,    0,  374,  374,
   86,    0,    0,   82,   82,    0,    0,    0,    0,   82,
   82,   82,   82,   82,   82,    0,    0,   82,   82,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   82,   82,   82,    0,   82,    0,    0,    0,    0,
    0,    0,   82,    0,   82,    0,    0,    0,    0,    0,
   82,   82,    0,    0,    0,    0,    0,    0,    0,    0,
   82,   82,   82,   82,   82,    0,   82,   82,   82,   82,
   82,   82,   82,   82,   82,    0,   82,    0,   82,   82,
   82,   82,   82,    0,   82,   82,   82,    0,    0,   82,
    0,   82,   82,   82,    0,    0,    0,    0,   82,    0,
    0,    0,    0,    0,   82,    0,    0,    0,    0,    0,
   82,   82,    0,   86,    0,   82,    0,    0,    0,    0,
   82,   86,   86,    0,   82,   82,   82,   82,   82,   82,
   82,    0,    0,    0,    0,   86,   86,    0,   82,    0,
    0,   82,   82,    0,  325,    0,   86,   86,    0,    0,
    0,    0,   86,   86,   86,   86,   86,   86,    0,    0,
   86,   86,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  450,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  450,    0,    0,   86,   86,   86,    0,   86,    0,
    0,    0,    0,    0,    0,   86,    0,   86,    0,    0,
    0,    0,    0,   86,   86,    0,    0,    0,    0,    0,
    0,    0,    0,   86,   86,   86,   86,   86,    0,   86,
   86,   86,   86,   86,   86,   86,   86,   86,    0,   86,
    0,   86,   86,   86,   86,   86,    0,   86,   86,   86,
    0,    0,   86,    0,   86,   86,   86,    0,    0,    0,
    0,   86,    0,    0,    0,    0,    0,   86,    0,    0,
    0,    0,    0,   86,   86,    0,    0,  325,   86,    0,
    0,    0,    0,   86,    0,  325,  325,   86,   86,   86,
   86,   86,   86,   86,    0,    0,    0,    0,    0,  325,
  325,   86,  325,    0,   86,   86,  450,    0,    0,    0,
  325,  325,    0,    0,  450,  450,  325,  325,  325,  325,
  325,  325,    0,    0,  325,  325,  325,    0,  450,  450,
    0,    0,    0,    0,  450,    0,    0,    0,    0,  450,
  450,    0,    0,    0,    0,  450,  450,  450,  450,  450,
  450,    0,    0,  450,  450,    0,    0,    0,    0,  450,
    0,    0,    0,    0,    0,    0,    0,    0,  325,  325,
    0,    0,  325,  450,  450,    0,    0,    0,    0,  325,
    0,  325,    0,  450,    0,    0,    0,  325,  325,    0,
    0,    0,    0,    0,    0,    0,    0,  450,  450,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  450,    0,
  450,    0,    0,    0,    0,    0,  450,  450,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  450,
    0,    0,    0,    0,    0,    0,    0,    0,  450,    0,
    0,  325,    0,    0,  450,  450,    0,  325,  325,    0,
    0,    0,  325,    0,    0,    0,    0,  325,    0,    0,
    0,  325,  325,  325,  325,  325,  325,  325,    0,    0,
  450,    0,    0,    0,    0,    0,  450,  450,  325,  325,
    0,    0,    0,    0,    0,    0,  450,    0,    0,  298,
  450,  450,  450,  450,  450,  450,  450,    5,    6,    0,
    0,    0,    0,    0,    0,  450,    0,  450,  450,  450,
    0,  335,  336,    0,  450,    0,    0,    0,    0,    0,
    0,    0,  337,  338,    0,    0,    0,    0,   40,   41,
   11,   12,   13,   14,    0,    0,  339,  340,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  341,  342,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  301,    0,    0,    0,    5,    6,  302,
  303,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  335,  336,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  337,  338,    0,    0,    0,    0,   40,   41,
   11,   12,   13,   14,    0,    0,  339,  340,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  343,    0,    0,    0,    0,    0,  344,
  304,    0,    0,    0,    0,    0,    0,    0,    0,  345,
    0,    0,    0,  346,  347,  348,  349,  350,  351,  352,
  341,    0,  391,    0,  300,    0,    0,    0,    0,    0,
  353,  354,    0,  301,    0,    0,    0,    0,    0,  302,
  303,    0,    0,    0,    0,    0,    0,    0,    0,  392,
  393,  394,  395,  396,    0,  397,  398,  399,  400,  401,
  402,  403,  404,  405,    0,  406,    0,  407,  408,  409,
  410,  411,    0,  412,  413,  414,    0,    0,  415,    0,
  416,  417,  418,    0,    0,    0,    0,  419,    0,    0,
    0,    0,    0,  343,    0,    0,    0,    0,    0,  344,
  304,    0,    0,    0,  305,    0,    0,    0,    0,  345,
    0,    0,    0,    0,  347,  348,  349,  350,  351,  352,
    0,    0,    0,    0,    0,    0,    0,  420,    0,    0,
  353,  354,
};
static const short socks_yycheck[] = {                    4,
    4,  167,  167,  254,    0,  157,   58,  272,  295,  272,
    0,    0,  292,  316,  272,  272,  125,  272,  296,   45,
  125,  125,  283,  297,  125,  242,  494,  458,  296,  297,
  260,  261,  125,  125,  468,  358,  296,  381,    2,    4,
    4,  296,  297,    4,  619,  335,  336,  137,  296,   58,
    4,  316,    4,  316,  257,  258,  259,   21,  316,  316,
  304,  316,  595,  239,  273,    4,  599,  276,  277,  278,
  614,  301,  302,  282,  283,  284,  285,   58,   83,   83,
    4,  290,  291,  162,  293,  299,   58,  296,  297,  298,
  623,   58,  706,  380,  274,  275,  305,  306,  307,  308,
  309,  310,  311,  312,  648,  319,  315,  316,  358,  270,
  271,  272,  202,   58,  358,  459,  730,  731,   83,   83,
  329,  330,   83,  332,  699,  469,  560,  558,  451,   83,
  342,   83,  382,  363,  343,   46,  125,  216,  352,  348,
  349,  350,  610,   58,   83,  354,  358,   58,  257,  258,
  259,  260,  261,  257,  258,  259,  257,  258,  259,   83,
  263,  264,  265,  266,  697,   58,  327,  370,  459,  460,
  461,  462,  463,  464,  382,  383,  384,  385,  386,  387,
  458,  355,  356,  444,  445,  446,  447,  440,  441,  442,
  458,  352,  301,  302,  468,  344,  345,  346,  458,   58,
  468,  279,  280,  458,  382,  383,  384,  385,  386,  439,
  458,  473,  474,  468,  364,  365,  366,  367,  368,  373,
  374,  375,  376,  377,  433,  434,  435,  382,  383,   58,
  385,  386,  287,  288,  289,   58,  523,  473,  474,  526,
  382,  383,  384,  385,  257,  258,  259,  473,  474,  382,
  383,  471,  472,    0,  363,  370,  371,   58,  467,  468,
   46,  370,   58,  440,  441,  370,  370,  272,  257,  258,
  259,  260,  261,   58,  270,  271,  272,  370,  370,  268,
  558,  270,  271,  272,  273,  502,  560,  276,  277,  278,
  558,   58,  560,  282,  283,  284,  285,  473,  558,  602,
   58,  290,  291,  558,  293,  560,  358,  296,  297,  298,
  558,  316,  301,  302,  473,  474,  305,  306,  307,  308,
  309,  310,  311,  312,   58,  501,  315,  316,  317,   58,
  439,  327,  358,  473,  474,  473,  474,  602,  327,  602,
  329,  330,   58,  332,  602,  602,   58,  602,  473,  474,
  473,  474,  449,  450,  343,   58,  352,  123,  124,  348,
  349,  350,  352,  352,  353,  354,  246,  247,  357,   58,
  359,  360,  361,   58,  363,   58,   58,   58,  125,   58,
   58,  370,  371,  372,   58,  437,  341,  358,  358,  378,
  379,   58,  358,   58,  352,  358,  358,   46,  358,  388,
  389,  390,  391,  392,   46,  394,  395,  396,  397,  398,
  399,  400,  401,  402,  358,  404,  294,  406,  407,  408,
  409,  410,   58,  412,  413,  414,   58,  358,  417,  331,
  419,  420,  421,  347,  313,   46,  313,  426,  286,  358,
  358,   46,   46,  432,  433,  434,  435,  314,  318,  438,
  439,  123,  318,  619,  443,  328,    0,  328,   46,  448,
  612,  613,   46,  452,  453,  454,  455,  456,  457,  458,
   47,  751,   47,   47,  357,  479,  123,  466,  467,  468,
  469,  470,   58,  358,  358,  736,  737,   58,   58,  123,
  123,  334,  123,  358,   58,   58,   58,   45,   58,   58,
   58,   58,   58,   58,   58,   58,  370,  370,   47,  292,
  257,  258,  259,  260,  261,   58,  358,   58,   58,  371,
   58,  268,   58,  270,  271,  272,  273,   58,   58,  276,
  277,  278,   58,  699,  699,  282,  283,  284,  285,   58,
   58,   58,   58,  290,  291,   58,  293,   58,   58,  296,
  297,  298,   58,   58,  301,  302,   58,   58,  305,  306,
  307,  308,  309,  310,  311,  312,   58,   58,  315,  316,
  317,   58,   58,   58,   58,   58,   58,   58,   58,   58,
  327,  125,  329,  330,   58,  332,   58,   58,   58,  593,
   58,   58,   58,   58,   58,   58,  343,  602,   58,   58,
   58,  348,  349,  350,   58,  352,  353,  354,   58,  269,
  357,  381,  359,  360,  361,  380,  363,   58,  371,   58,
  353,  358,   46,  370,  371,  372,   46,  358,  358,   58,
  436,  378,  379,  451,  358,  371,   58,  358,  465,  358,
  358,  388,  389,  390,  391,  392,  347,  394,  395,  396,
  397,  398,  399,  400,  401,  402,  300,  404,   58,  406,
  407,  408,  409,  410,  362,  412,  413,  414,  429,  429,
  417,    0,  419,  420,  421,  429,  393,  429,  393,  426,
  393,  430,  358,  431,  428,  432,  433,  434,  435,  358,
  358,  438,  439,  428,  405,  415,  443,  411,   46,  358,
  428,  448,  428,  411,  411,  452,  453,  454,  455,  456,
  457,  458,  418,  257,  258,  259,  260,  261,  427,  466,
  467,  468,  469,  470,  268,   58,  270,  271,  272,  273,
   58,   58,  276,  277,  278,   47,  302,   47,  282,  283,
  284,  285,  125,  125,  358,   45,  290,  291,  125,  293,
  125,  358,  296,  297,  298,  267,  125,  301,  302,   46,
   46,  305,  306,  307,  308,  309,  310,  311,  312,  358,
  357,  315,  316,  317,   58,  358,  358,   47,  358,  437,
  358,    0,  351,  327,  351,  329,  330,    0,  332,  370,
  358,  370,   58,  358,  125,  125,  125,  370,  574,  343,
  125,  645,  593,  587,  348,  349,  350,  175,  352,  353,
  354,  642,   21,  357,  565,  359,  360,  361,  152,  363,
  320,  159,  492,   83,  132,  259,  370,  371,  372,  524,
  167,  167,  629,  738,  378,  379,  639,  345,  390,  581,
   -1,   -1,   -1,  509,  388,  389,  390,  391,  392,   -1,
  394,  395,  396,  397,  398,  399,  400,  401,  402,   -1,
  404,   -1,  406,  407,  408,  409,  410,   -1,  412,  413,
  414,   -1,   -1,  417,    0,  419,  420,  421,   -1,   -1,
   -1,   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,  433,
  434,  435,   -1,   -1,  438,  439,   -1,   -1,   -1,  443,
   -1,   -1,   -1,   -1,  448,   -1,   -1,   -1,  452,  453,
  454,  455,  456,  457,  458,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  466,  467,  468,  469,  470,   -1,  257,  258,
  259,  260,  261,   -1,   -1,   -1,   -1,   -1,   -1,  268,
   -1,  270,  271,  272,  273,   -1,   -1,  276,  277,  278,
   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,   -1,
   -1,  290,  291,   -1,  293,   -1,   -1,  296,  297,  298,
   -1,   -1,  301,  302,   -1,   -1,  305,  306,  307,  308,
  309,  310,  311,  312,   -1,   -1,  315,  316,  317,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,  125,
  329,  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,   -1,  348,
  349,  350,   -1,  352,  353,  354,   -1,   -1,   -1,   -1,
  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,
   -1,  370,  371,  372,   -1,   -1,   -1,   -1,   -1,  378,
  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,
  389,  390,  391,  392,   -1,  394,  395,  396,  397,  398,
  399,  400,  401,  402,   -1,  404,   -1,  406,  407,  408,
  409,  410,    0,  412,  413,  414,   -1,   -1,  417,   -1,
  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,
   -1,   -1,   -1,  432,  433,  434,  435,   -1,   -1,  438,
  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,  448,
   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,  458,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,  467,  468,
  469,  470,  268,   -1,  270,  271,  272,  273,   -1,   -1,
  276,  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,
   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,
  296,  297,  298,   -1,   -1,  301,  302,   -1,   -1,  305,
  306,  307,  308,  309,  310,  311,  312,   -1,   -1,  315,
  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  327,   -1,  329,  330,   -1,  332,  125,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,
   -1,   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,
   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,   -1,
   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,
   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,  395,
  396,  397,  398,  399,  400,  401,  402,   -1,  404,   -1,
  406,  407,  408,  409,  410,    0,  412,  413,  414,   -1,
   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,
  426,   -1,   -1,   -1,   -1,   -1,  432,  433,  434,  435,
   -1,   -1,  438,  439,   -1,   -1,   -1,  443,   -1,   -1,
   -1,   -1,  448,   -1,   -1,   -1,  452,  453,  454,  455,
  456,  457,  458,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  466,  467,  468,  469,  470,   -1,   -1,   -1,   -1,   -1,
  268,   -1,  270,  271,  272,  273,   -1,   -1,  276,  277,
  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,   -1,
   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,  297,
  298,   -1,   -1,  301,  302,   -1,   -1,  305,  306,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,
  125,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,   -1,
  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,   -1,
   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,
  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  388,  389,  390,  391,  392,   -1,  394,  395,  396,  397,
  398,  399,  400,  401,  402,   -1,  404,   -1,  406,  407,
  408,  409,  410,    0,  412,  413,  414,   -1,   -1,  417,
   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,
   -1,   -1,   -1,   -1,  432,  433,  434,  435,   -1,   -1,
  438,  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,
  448,   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,
  458,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,  467,
  468,  469,  470,  268,   -1,  270,  271,  272,  273,   -1,
   -1,  276,  277,  278,   -1,   -1,   -1,  282,  283,  284,
  285,   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,
   -1,  296,  297,  298,   -1,   -1,  301,  302,   -1,   -1,
  305,  306,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  327,   -1,  329,  330,   -1,  332,  125,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,
   -1,   -1,   -1,  348,  349,  350,   -1,  352,   -1,  354,
   -1,   -1,   -1,   -1,  359,  360,  361,   -1,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,
   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,
  395,  396,  397,  398,  399,  400,  401,  402,   -1,  404,
   -1,  406,  407,  408,  409,  410,    0,  412,  413,  414,
   -1,   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,
   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,  433,  434,
  435,   -1,   -1,  438,  439,   -1,   -1,   -1,  443,   -1,
   -1,   -1,   -1,  448,   -1,   -1,   -1,  452,  453,  454,
  455,  456,  457,  458,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  466,  467,  468,  469,  470,   -1,   -1,   -1,   -1,
   -1,  268,   -1,  270,  271,  272,  273,   -1,   -1,  276,
  277,  278,   -1,   -1,   -1,  282,  283,  284,  285,   -1,
   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,
  297,  298,   -1,   -1,  301,  302,   -1,   -1,  305,  306,
  307,  308,  309,  310,  311,  312,   -1,   -1,  315,  316,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  327,  125,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,   -1,
   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,
   -1,   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,
   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,
   -1,  378,  379,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,  388,  389,  390,  391,  392,   -1,  394,  395,  396,
  397,  398,  399,  400,  401,  402,   -1,  404,   -1,  406,
  407,  408,  409,  410,   -1,  412,  413,  414,   -1,   -1,
  417,   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,
   -1,   -1,   -1,   -1,   -1,  432,  433,  434,  435,   -1,
   -1,  438,  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,
   -1,  448,   -1,   -1,   -1,  452,  453,  454,  455,  456,
  457,  458,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,
  467,  468,  469,  470,  268,   -1,  270,  271,  272,  273,
    0,   -1,  276,  277,  278,   -1,   -1,   -1,  282,  283,
  284,  285,   -1,   -1,   -1,   -1,  290,  291,   -1,  293,
   -1,   -1,  296,  297,  298,   -1,   -1,   -1,   -1,   -1,
   -1,  305,  306,  307,  308,  309,  310,  311,  312,   -1,
   -1,  315,  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  327,   -1,  329,  330,   -1,  332,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,
   -1,   -1,   -1,   -1,  348,  349,  350,   -1,  352,   -1,
  354,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,
   -1,   -1,   -1,    0,  276,  277,  370,   -1,  372,   -1,
  282,  283,  284,  285,  378,  379,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  309,  310,  311,
  312,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  332,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  433,
  434,  435,   -1,   -1,   -1,  439,   -1,   -1,   -1,  443,
   -1,   -1,  354,   -1,  448,  270,  271,  272,  273,   -1,
   -1,  276,  277,  278,   -1,   -1,   -1,  282,  283,  284,
  285,   -1,   -1,  467,  468,  290,  291,   -1,  293,   -1,
   -1,  296,  297,  298,    0,   -1,   -1,   -1,   -1,   -1,
  305,  306,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  327,   -1,  329,  330,   -1,  332,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,
   -1,   -1,   -1,  348,  349,  350,   -1,  352,   -1,  354,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  270,  271,  272,  273,   -1,   -1,  276,  277,  278,   -1,
   -1,   -1,  282,  283,  284,  285,   -1,   -1,   -1,   -1,
  290,  291,    0,  293,   -1,   -1,  296,  297,  298,   -1,
   -1,   -1,   -1,   -1,   -1,  305,  306,  307,  308,  309,
  310,  311,  312,   -1,   -1,  315,  316,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,   -1,  329,
  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,  433,  434,
  435,   -1,   -1,  343,   -1,   -1,   -1,   -1,  348,  349,
  350,   -1,  352,   -1,  354,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  270,  271,  272,  273,   -1,   -1,  276,
  277,  278,  467,  468,   -1,  282,  283,  284,  285,   -1,
   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,  296,
  297,  298,   -1,   -1,   -1,   -1,   -1,   -1,  305,  306,
  307,  308,  309,  310,  311,  312,   -1,   -1,  315,  316,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  327,   -1,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  433,  434,  435,  343,   -1,   -1,   -1,
   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  467,  468,   -1,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,   -1,   -1,
  276,  277,  278,  268,   -1,   -1,  282,  283,  284,  285,
   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,   -1,
  296,  297,  298,   -1,   -1,   -1,   -1,   -1,  293,  305,
  306,  307,  308,  309,  310,  311,  312,  125,   -1,  315,
  316,   -1,  307,  308,   -1,   -1,  433,  434,  435,   -1,
   -1,  327,  317,  329,  330,   -1,  332,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  343,   -1,   -1,
   -1,   -1,  348,  349,  350,   -1,  352,   -1,  354,   -1,
  467,  468,  270,  271,  272,  273,   -1,   -1,  276,  277,
  278,   -1,   -1,   -1,  282,  283,  284,  285,  363,   -1,
   -1,   -1,  290,  291,   -1,  293,   -1,  372,  296,  297,
  298,   -1,   -1,  378,  379,   -1,   -1,  305,  306,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  327,
   -1,  329,  330,   -1,  332,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  343,   -1,  433,  434,  435,
  348,  349,  350,   -1,  352,   -1,  354,   -1,   -1,  257,
  258,  259,  260,  261,  439,   -1,   -1,   -1,  443,   -1,
  268,   -1,   -1,  448,   -1,   -1,   -1,   -1,  276,  277,
   -1,  467,  468,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  290,  291,   -1,  293,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  301,  302,   -1,   -1,   -1,   -1,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,  317,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  125,   -1,   -1,   -1,   -1,  433,  434,  435,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,  467,
  468,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,
  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  388,  389,  390,  391,  392,   -1,  394,  395,  396,  397,
  398,  399,  400,  401,  402,   -1,  404,   -1,  406,  407,
  408,  409,  410,   -1,  412,  413,  414,   -1,   -1,  417,
   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,
   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,   -1,
  438,  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,
  448,   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,
  458,   -1,  257,  258,  259,  260,  261,   -1,  466,   -1,
   -1,  469,  470,  268,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  276,  277,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  290,  291,   -1,  293,   -1,
   -1,   -1,   -1,   -1,  125,   -1,  301,  302,   -1,   -1,
   -1,   -1,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  359,   -1,  361,   -1,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,
   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,
  395,  396,  397,  398,  399,  400,  401,  402,   -1,  404,
   -1,  406,  407,  408,  409,  410,   -1,  412,  413,  414,
   -1,   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,
   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,   -1,
   -1,   -1,   -1,  438,  439,   -1,   -1,  268,  443,   -1,
   -1,   -1,   -1,  448,   -1,  276,  277,   -1,  453,  454,
  455,  456,  457,  458,   -1,   -1,   -1,   -1,   -1,  290,
  291,  466,  293,   -1,  469,  470,   -1,  125,   -1,   -1,
  301,  302,   -1,   -1,   -1,   -1,  307,  308,  309,  310,
  311,  312,   -1,   -1,  315,  316,  317,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  359,  360,
  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,
   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,  379,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,  389,  390,
  391,  392,   -1,  394,  395,  396,  397,  398,  399,  400,
  401,  402,   -1,  404,   -1,  406,  407,  408,  409,  410,
   -1,  412,  413,  414,   -1,   -1,  417,   -1,  419,  420,
  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,   -1,   -1,
   -1,  432,   -1,   -1,   -1,   -1,   -1,  438,  439,   -1,
  268,   -1,  443,   -1,   -1,   -1,   -1,  448,  276,  277,
   -1,  452,  453,  454,  455,  456,  457,  458,   -1,   -1,
   -1,   -1,  290,  291,   -1,  466,   -1,   -1,  469,  470,
   -1,  125,   -1,  301,  302,   -1,   -1,   -1,   -1,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,
  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  388,  389,  390,  391,  392,   -1,  394,  395,  396,  397,
  398,  399,  400,  401,  402,   -1,  404,   -1,  406,  407,
  408,  409,  410,   -1,  412,  413,  414,   -1,   -1,  417,
   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,
   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,   -1,
  438,  439,   -1,   -1,  268,  443,   -1,   -1,   -1,   -1,
  448,   -1,  276,  277,  452,  453,  454,  455,  456,  457,
  458,   -1,   -1,   -1,   -1,   -1,  290,  291,  466,  293,
   -1,  469,  470,   -1,  125,   -1,   -1,  301,  302,   -1,
   -1,   -1,   -1,  307,  308,  309,  310,  311,  312,   -1,
   -1,  315,  316,  317,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  359,   -1,  361,   -1,  363,
   -1,   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,
   -1,   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,
  394,  395,  396,  397,  398,  399,  400,  401,  402,   -1,
  404,   -1,  406,  407,  408,  409,  410,   -1,  412,  413,
  414,   -1,   -1,  417,   -1,  419,  420,  421,   -1,   -1,
   -1,   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,
   -1,   -1,   -1,   -1,  438,  439,   -1,  268,   -1,  443,
   -1,   -1,   -1,   -1,  448,  276,  277,   -1,   -1,  453,
  454,  455,  456,  457,  458,   -1,   -1,   -1,   -1,  290,
  291,   -1,  466,   -1,   -1,  469,  470,  125,   -1,   -1,
  301,  302,   -1,   -1,   -1,   -1,  307,  308,  309,  310,
  311,  312,   -1,   -1,  315,  316,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  359,  360,
  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,   -1,  370,
   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,  379,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,  389,  390,
  391,  392,   -1,  394,  395,  396,  397,  398,  399,  400,
  401,  402,   -1,  404,   -1,  406,  407,  408,  409,  410,
   -1,  412,  413,  414,   -1,   -1,  417,   -1,  419,  420,
  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,   -1,   -1,
   -1,  432,   -1,   -1,   -1,   -1,   -1,  438,  439,   -1,
  268,   -1,  443,   -1,   -1,   -1,   -1,  448,  276,  277,
   -1,  452,  453,  454,  455,  456,  457,  458,   -1,   -1,
   -1,   -1,  290,  291,   -1,  466,   -1,   -1,  469,  470,
  125,   -1,   -1,  301,  302,   -1,   -1,   -1,   -1,  307,
  308,  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  359,  360,  361,   -1,  363,   -1,   -1,   -1,   -1,
   -1,   -1,  370,   -1,  372,   -1,   -1,   -1,   -1,   -1,
  378,  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  388,  389,  390,  391,  392,   -1,  394,  395,  396,  397,
  398,  399,  400,  401,  402,   -1,  404,   -1,  406,  407,
  408,  409,  410,   -1,  412,  413,  414,   -1,   -1,  417,
   -1,  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,
   -1,   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,   -1,
  438,  439,   -1,  268,   -1,  443,   -1,   -1,   -1,   -1,
  448,  276,  277,   -1,  452,  453,  454,  455,  456,  457,
  458,   -1,   -1,   -1,   -1,  290,  291,   -1,  466,   -1,
   -1,  469,  470,   -1,  125,   -1,  301,  302,   -1,   -1,
   -1,   -1,  307,  308,  309,  310,  311,  312,   -1,   -1,
  315,  316,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  125,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  125,   -1,   -1,  359,  360,  361,   -1,  363,   -1,
   -1,   -1,   -1,   -1,   -1,  370,   -1,  372,   -1,   -1,
   -1,   -1,   -1,  378,  379,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  388,  389,  390,  391,  392,   -1,  394,
  395,  396,  397,  398,  399,  400,  401,  402,   -1,  404,
   -1,  406,  407,  408,  409,  410,   -1,  412,  413,  414,
   -1,   -1,  417,   -1,  419,  420,  421,   -1,   -1,   -1,
   -1,  426,   -1,   -1,   -1,   -1,   -1,  432,   -1,   -1,
   -1,   -1,   -1,  438,  439,   -1,   -1,  268,  443,   -1,
   -1,   -1,   -1,  448,   -1,  276,  277,  452,  453,  454,
  455,  456,  457,  458,   -1,   -1,   -1,   -1,   -1,  290,
  291,  466,  293,   -1,  469,  470,  268,   -1,   -1,   -1,
  301,  302,   -1,   -1,  276,  277,  307,  308,  309,  310,
  311,  312,   -1,   -1,  315,  316,  317,   -1,  290,  291,
   -1,   -1,   -1,   -1,  268,   -1,   -1,   -1,   -1,  301,
  302,   -1,   -1,   -1,   -1,  307,  308,  309,  310,  311,
  312,   -1,   -1,  315,  316,   -1,   -1,   -1,   -1,  293,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  359,  360,
   -1,   -1,  363,  307,  308,   -1,   -1,   -1,   -1,  370,
   -1,  372,   -1,  317,   -1,   -1,   -1,  378,  379,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  359,  360,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  370,   -1,
  372,   -1,   -1,   -1,   -1,   -1,  378,  379,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  363,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  372,   -1,
   -1,  432,   -1,   -1,  378,  379,   -1,  438,  439,   -1,
   -1,   -1,  443,   -1,   -1,   -1,   -1,  448,   -1,   -1,
   -1,  452,  453,  454,  455,  456,  457,  458,   -1,   -1,
  432,   -1,   -1,   -1,   -1,   -1,  438,  439,  469,  470,
   -1,   -1,   -1,   -1,   -1,   -1,  448,   -1,   -1,  268,
  452,  453,  454,  455,  456,  457,  458,  276,  277,   -1,
   -1,   -1,   -1,   -1,   -1,  439,   -1,  469,  470,  443,
   -1,  290,  291,   -1,  448,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  301,  302,   -1,   -1,   -1,   -1,  307,  308,
  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  359,  360,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  372,   -1,   -1,   -1,  276,  277,  378,
  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  290,  291,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  301,  302,   -1,   -1,   -1,   -1,  307,  308,
  309,  310,  311,  312,   -1,   -1,  315,  316,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,   -1,  438,
  439,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  448,
   -1,   -1,   -1,  452,  453,  454,  455,  456,  457,  458,
  359,   -1,  361,   -1,  363,   -1,   -1,   -1,   -1,   -1,
  469,  470,   -1,  372,   -1,   -1,   -1,   -1,   -1,  378,
  379,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  388,
  389,  390,  391,  392,   -1,  394,  395,  396,  397,  398,
  399,  400,  401,  402,   -1,  404,   -1,  406,  407,  408,
  409,  410,   -1,  412,  413,  414,   -1,   -1,  417,   -1,
  419,  420,  421,   -1,   -1,   -1,   -1,  426,   -1,   -1,
   -1,   -1,   -1,  432,   -1,   -1,   -1,   -1,   -1,  438,
  439,   -1,   -1,   -1,  443,   -1,   -1,   -1,   -1,  448,
   -1,   -1,   -1,   -1,  453,  454,  455,  456,  457,  458,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  466,   -1,   -1,
  469,  470,
};
#define YYFINAL 3
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 474
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,"'-'","'.'","'/'",0,0,0,0,0,0,0,0,0,0,"':'",0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"ALARM",
"ALARMTYPE_DATA","ALARMTYPE_DISCONNECT","ALARMIF_INTERNAL","ALARMIF_EXTERNAL",
"TCPOPTION_DISABLED","ECN","SACK","TIMESTAMPS","WSCALE","MTU_ERROR",
"CLIENTCOMPATIBILITY","NECGSSAPI","CLIENTRULE","HOSTIDRULE","SOCKSRULE",
"COMPATIBILITY","SAMEPORT","DRAFT_5_05","CONNECTTIMEOUT","TCP_FIN_WAIT","CPU",
"MASK","SCHEDULE","CPUMASK_ANYCPU","DEBUGGING","DEPRECATED","ERRORLOG",
"LOGOUTPUT","LOGFILE","LOGTYPE_ERROR","LOGTYPE_TCP_DISABLED",
"LOGTYPE_TCP_ENABLED","LOGIF_INTERNAL","LOGIF_EXTERNAL","ERRORVALUE",
"EXTENSION","BIND","PRIVILEGED","EXTERNAL_PROTOCOL","INTERNAL_PROTOCOL",
"EXTERNAL_ROTATION","SAMESAME","GROUPNAME","HOSTID","HOSTINDEX","INTERFACE",
"SOCKETOPTION_SYMBOLICVALUE","INTERNAL","EXTERNAL","INTERNALSOCKET",
"EXTERNALSOCKET","IOTIMEOUT","IOTIMEOUT_TCP","IOTIMEOUT_UDP","NEGOTIATETIMEOUT",
"LIBWRAP_FILE","LOGLEVEL","SOCKSMETHOD","CLIENTMETHOD","METHOD","METHODNAME",
"NONE","BSDAUTH","GSSAPI","PAM_ADDRESS","PAM_ANY","PAM_USERNAME","RFC931",
"UNAME","MONITOR","PROCESSTYPE","PROC_MAXREQUESTS","REALM","REALNAME",
"RESOLVEPROTOCOL","REQUIRED","SCHEDULEPOLICY","SERVERCONFIG","CLIENTCONFIG",
"SOCKET","CLIENTSIDE_SOCKET","SNDBUF","RCVBUF","SOCKETPROTOCOL",
"SOCKETOPTION_OPTID","SRCHOST","NODNSMISMATCH","NODNSUNKNOWN","CHECKREPLYAUTH",
"USERNAME","USER_PRIVILEGED","USER_UNPRIVILEGED","USER_LIBWRAP","WORD__IN",
"ROUTE","VIA","GLOBALROUTEOPTION","BADROUTE_EXPIRE","MAXFAIL","PORT","NUMBER",
"BANDWIDTH","BOUNCE","BSDAUTHSTYLE","BSDAUTHSTYLENAME","COMMAND","COMMAND_BIND",
"COMMAND_CONNECT","COMMAND_UDPASSOCIATE","COMMAND_BINDREPLY","COMMAND_UDPREPLY",
"ACTION","FROM","TO","GSSAPIENCTYPE","GSSAPIENC_ANY","GSSAPIENC_CLEAR",
"GSSAPIENC_INTEGRITY","GSSAPIENC_CONFIDENTIALITY","GSSAPIENC_PERMESSAGE",
"GSSAPIKEYTAB","GSSAPISERVICE","GSSAPISERVICENAME","GSSAPIKEYTABNAME","IPV4",
"IPV6","IPVANY","DOMAINNAME","IFNAME","URL","LDAPATTRIBUTE","LDAPATTRIBUTE_AD",
"LDAPATTRIBUTE_HEX","LDAPATTRIBUTE_AD_HEX","LDAPBASEDN","LDAP_BASEDN",
"LDAPBASEDN_HEX","LDAPBASEDN_HEX_ALL","LDAPCERTFILE","LDAPCERTPATH","LDAPPORT",
"LDAPPORTSSL","LDAPDEBUG","LDAPDEPTH","LDAPAUTO","LDAPSEARCHTIME","LDAPDOMAIN",
"LDAP_DOMAIN","LDAPFILTER","LDAPFILTER_AD","LDAPFILTER_HEX","LDAPFILTER_AD_HEX",
"LDAPGROUP","LDAPGROUP_NAME","LDAPGROUP_HEX","LDAPGROUP_HEX_ALL","LDAPKEYTAB",
"LDAPKEYTABNAME","LDAPDEADTIME","LDAPSERVER","LDAPSERVER_NAME","LDAPSSL",
"LDAPCERTCHECK","LDAPKEEPREALM","LDAPTIMEOUT","LDAPCACHE","LDAPCACHEPOS",
"LDAPCACHENEG","LDAPURL","LDAP_URL","LDAP_FILTER","LDAP_ATTRIBUTE",
"LDAP_CERTFILE","LDAP_CERTPATH","LIBWRAPSTART","LIBWRAP_ALLOW","LIBWRAP_DENY",
"LIBWRAP_HOSTS_ACCESS","LINE","OPERATOR","PAMSERVICENAME","PROTOCOL",
"PROTOCOL_TCP","PROTOCOL_UDP","PROTOCOL_FAKE","PROXYPROTOCOL",
"PROXYPROTOCOL_SOCKS_V4","PROXYPROTOCOL_SOCKS_V5","PROXYPROTOCOL_HTTP",
"PROXYPROTOCOL_UPNP","REDIRECT","SENDSIDE","RECVSIDE","SERVICENAME",
"SESSION_INHERITABLE","SESSIONMAX","SESSIONTHROTTLE","SESSIONSTATE_KEY",
"SESSIONSTATE_MAX","SESSIONSTATE_THROTTLE","RULE_LOG","RULE_LOG_CONNECT",
"RULE_LOG_DATA","RULE_LOG_DISCONNECT","RULE_LOG_ERROR","RULE_LOG_IOOPERATION",
"RULE_LOG_TCPINFO","STATEKEY","UDPPORTRANGE","UDPCONNECTDST","DNSRESOLVDST",
"USER","GROUP","VERDICT_BLOCK","VERDICT_PASS","YES","NO",
};
static const char *yyrule[] = {
"$accept : configtype",
"$$1 :",
"configtype : SERVERCONFIG $$1 serveroptions serverobjects",
"configtype : CLIENTCONFIG clientoptions routes",
"serverobjects :",
"serverobjects : serverobjects serverobject",
"serverobject : crule",
"serverobject : hrule",
"serverobject : srule",
"serverobject : monitor",
"serverobject : route",
"serveroptions :",
"serveroptions : serveroption serveroptions",
"serveroption : childstate",
"serveroption : compatibility",
"serveroption : cpu",
"serveroption : debugging",
"serveroption : deprecated",
"serveroption : errorlog",
"serveroption : extension",
"serveroption : external",
"serveroption : external_protocol",
"serveroption : external_rotation",
"serveroption : external_if_logoption",
"serveroption : global_clientmethod",
"serveroption : global_socksmethod",
"serveroption : global_routeoption",
"serveroption : internal",
"serveroption : internal_protocol",
"serveroption : internal_if_logoption",
"serveroption : libwrap_hosts_access",
"serveroption : libwrapfiles",
"serveroption : logoutput",
"serveroption : realm",
"serveroption : resolveprotocol",
"serveroption : srchost",
"serveroption : timeout",
"serveroption : udpconnectdst",
"serveroption : dnsresolvdst",
"serveroption : userids",
"serveroption : socketoption",
"logspecial : LOGTYPE_ERROR ':' errors",
"$$2 :",
"logspecial : LOGTYPE_TCP_DISABLED ':' $$2 tcpoptions",
"$$3 :",
"logspecial : LOGTYPE_TCP_ENABLED ':' $$3 tcpoptions",
"$$4 :",
"internal_if_logoption : LOGIF_INTERNAL $$4 '.' loglevel '.' logspecial",
"$$5 :",
"external_if_logoption : LOGIF_EXTERNAL $$5 '.' loglevel '.' logspecial",
"$$6 :",
"rule_internal_logoption : LOGIF_INTERNAL $$6 '.' loglevel '.' logspecial",
"$$7 :",
"rule_external_logoption : LOGIF_EXTERNAL $$7 '.' loglevel '.' logspecial",
"loglevel : LOGLEVEL",
"tcpoptions : tcpoption",
"tcpoptions : tcpoption tcpoptions",
"tcpoption : ECN",
"tcpoption : SACK",
"tcpoption : TIMESTAMPS",
"tcpoption : WSCALE",
"errors : errorobject",
"errors : errorobject errors",
"errorobject : ERRORVALUE",
"timeout : connecttimeout",
"timeout : iotimeout",
"timeout : negotiatetimeout",
"timeout : tcp_fin_timeout",
"deprecated : DEPRECATED",
"$$8 :",
"$$9 :",
"route : ROUTE $$8 '{' $$9 routeoptions fromto gateway routeoptions '}'",
"routes :",
"routes : routes route",
"proxyprotocol : PROXYPROTOCOL ':' proxyprotocols",
"proxyprotocolname : PROXYPROTOCOL_SOCKS_V4",
"proxyprotocolname : PROXYPROTOCOL_SOCKS_V5",
"proxyprotocolname : PROXYPROTOCOL_HTTP",
"proxyprotocolname : PROXYPROTOCOL_UPNP",
"proxyprotocolname : deprecated",
"proxyprotocols : proxyprotocolname",
"proxyprotocols : proxyprotocolname proxyprotocols",
"user : USER ':' usernames",
"username : USERNAME",
"usernames : username",
"usernames : usernames username",
"group : GROUP ':' groupnames",
"groupname : GROUPNAME",
"groupnames : groupname",
"groupnames : groupnames groupname",
"extension : EXTENSION ':' extensions",
"extensionname : BIND",
"extensions : extensionname",
"extensions : extensionname extensions",
"ifprotocols : ifprotocol",
"ifprotocols : ifprotocol ifprotocols",
"ifprotocol : IPV4",
"ifprotocol : IPV6",
"internal : INTERNAL internalinit ':' address",
"internalinit :",
"$$10 :",
"internal_protocol : INTERNAL_PROTOCOL ':' $$10 ifprotocols",
"external : EXTERNAL externalinit ':' externaladdress",
"externalinit :",
"$$11 :",
"external_protocol : EXTERNAL_PROTOCOL ':' $$11 ifprotocols",
"external_rotation : EXTERNAL_ROTATION ':' NONE",
"external_rotation : EXTERNAL_ROTATION ':' SAMESAME",
"external_rotation : EXTERNAL_ROTATION ':' ROUTE",
"clientoption : debugging",
"clientoption : deprecated",
"clientoption : global_routeoption",
"clientoption : errorlog",
"clientoption : logoutput",
"clientoption : resolveprotocol",
"clientoption : timeout",
"clientoptions :",
"clientoptions : clientoption clientoptions",
"global_routeoption : GLOBALROUTEOPTION MAXFAIL ':' NUMBER",
"global_routeoption : GLOBALROUTEOPTION BADROUTE_EXPIRE ':' NUMBER",
"$$12 :",
"errorlog : ERRORLOG ':' $$12 logoutputdevices",
"$$13 :",
"logoutput : LOGOUTPUT ':' $$13 logoutputdevices",
"logoutputdevice : LOGFILE",
"logoutputdevices : logoutputdevice",
"logoutputdevices : logoutputdevice logoutputdevices",
"childstate : PROC_MAXREQUESTS ':' NUMBER",
"userids : user_privileged",
"userids : user_unprivileged",
"userids : user_libwrap",
"user_privileged : USER_PRIVILEGED ':' userid",
"user_unprivileged : USER_UNPRIVILEGED ':' userid",
"user_libwrap : USER_LIBWRAP ':' userid",
"userid : USERNAME",
"iotimeout : IOTIMEOUT ':' NUMBER",
"iotimeout : IOTIMEOUT_TCP ':' NUMBER",
"iotimeout : IOTIMEOUT_UDP ':' NUMBER",
"negotiatetimeout : NEGOTIATETIMEOUT ':' NUMBER",
"connecttimeout : CONNECTTIMEOUT ':' NUMBER",
"tcp_fin_timeout : TCP_FIN_WAIT ':' NUMBER",
"debugging : DEBUGGING ':' NUMBER",
"libwrapfiles : libwrap_allowfile",
"libwrapfiles : libwrap_denyfile",
"libwrap_allowfile : LIBWRAP_ALLOW ':' LIBWRAP_FILE",
"libwrap_denyfile : LIBWRAP_DENY ':' LIBWRAP_FILE",
"libwrap_hosts_access : LIBWRAP_HOSTS_ACCESS ':' YES",
"libwrap_hosts_access : LIBWRAP_HOSTS_ACCESS ':' NO",
"udpconnectdst : UDPCONNECTDST ':' YES",
"udpconnectdst : UDPCONNECTDST ':' NO",
"dnsresolvdst : DNSRESOLVDST ':' YES",
"dnsresolvdst : DNSRESOLVDST ':' NO",
"compatibility : COMPATIBILITY ':' compatibilitynames",
"compatibilityname : SAMEPORT",
"compatibilityname : DRAFT_5_05",
"compatibilitynames : compatibilityname",
"compatibilitynames : compatibilityname compatibilitynames",
"resolveprotocol : RESOLVEPROTOCOL ':' resolveprotocolname",
"resolveprotocolname : PROTOCOL_FAKE",
"resolveprotocolname : PROTOCOL_TCP",
"resolveprotocolname : PROTOCOL_UDP",
"cpu : cpuschedule",
"cpu : cpuaffinity",
"cpuschedule : CPU '.' SCHEDULE '.' PROCESSTYPE ':' SCHEDULEPOLICY '/' NUMBER",
"cpuaffinity : CPU '.' MASK '.' PROCESSTYPE ':' numbers",
"$$14 :",
"socketoption : socketside SOCKETPROTOCOL '.' $$14 socketoptionname ':' socketoptionvalue",
"socketoptionname : NUMBER",
"socketoptionname : SOCKETOPTION_OPTID",
"socketoptionvalue : NUMBER",
"socketoptionvalue : SOCKETOPTION_SYMBOLICVALUE",
"socketside : INTERNALSOCKET",
"socketside : EXTERNALSOCKET",
"srchost : SRCHOST ':' srchostoptions",
"srchostoption : NODNSMISMATCH",
"srchostoption : NODNSUNKNOWN",
"srchostoption : CHECKREPLYAUTH",
"srchostoptions : srchostoption",
"srchostoptions : srchostoption srchostoptions",
"realm : REALM ':' REALNAME",
"$$15 :",
"global_clientmethod : CLIENTMETHOD ':' $$15 clientmethods",
"$$16 :",
"global_socksmethod : SOCKSMETHOD ':' $$16 socksmethods",
"socksmethod : SOCKSMETHOD ':' socksmethods",
"socksmethods : socksmethodname",
"socksmethods : socksmethodname socksmethods",
"socksmethodname : METHODNAME",
"clientmethod : CLIENTMETHOD ':' clientmethods",
"clientmethods : clientmethodname",
"clientmethods : clientmethodname clientmethods",
"clientmethodname : METHODNAME",
"$$17 :",
"$$18 :",
"monitor : MONITOR $$17 '{' $$18 monitoroptions fromto monitoroptions '}'",
"$$19 :",
"crule : CLIENTRULE $$19 verdict '{' cruleoptions fromto cruleoptions '}'",
"alarm : alarm_data",
"alarm : alarm_disconnect",
"alarm : alarm_test",
"monitorside :",
"monitorside : ALARMIF_INTERNAL",
"monitorside : ALARMIF_EXTERNAL",
"alarmside :",
"alarmside : RECVSIDE",
"alarmside : SENDSIDE",
"$$20 :",
"alarm_data : monitorside ALARMTYPE_DATA $$20 alarmside ':' NUMBER WORD__IN NUMBER",
"alarm_test : monitorside ALARM '.' networkproblem",
"networkproblem : MTU_ERROR",
"alarm_disconnect : monitorside ALARMTYPE_DISCONNECT ':' NUMBER '/' NUMBER alarmperiod",
"alarmperiod :",
"alarmperiod : WORD__IN NUMBER",
"monitoroption : alarm",
"monitoroption : command",
"monitoroption : hostidoption",
"monitoroption : protocol",
"monitoroptions :",
"monitoroptions : monitoroption monitoroptions",
"cruleoption : bounce",
"cruleoption : protocol",
"cruleoption : clientcompatibility",
"cruleoption : crulesessionoption",
"cruleoption : genericruleoption",
"$$21 :",
"hrule : HOSTIDRULE $$21 verdict '{' cruleoptions hostid_fromto cruleoptions '}'",
"cruleoptions :",
"cruleoptions : cruleoption cruleoptions",
"hostidoption : hostid",
"hostidoption : hostindex",
"$$22 :",
"hostid : HOSTID ':' $$22 address_without_port",
"hostindex : HOSTINDEX ':' NUMBER",
"$$23 :",
"srule : SOCKSRULE $$23 verdict '{' sruleoptions fromto sruleoptions '}'",
"sruleoptions :",
"sruleoptions : sruleoption sruleoptions",
"sruleoption : bsdauthstylename",
"sruleoption : command",
"sruleoption : genericruleoption",
"sruleoption : ldapoption",
"sruleoption : protocol",
"sruleoption : proxyprotocol",
"sruleoption : sockssessionoption",
"sruleoption : udpportrange",
"genericruleoption : bandwidth",
"genericruleoption : clientmethod",
"genericruleoption : socksmethod",
"genericruleoption : rule_external_logoption",
"genericruleoption : group",
"genericruleoption : gssapienctype",
"genericruleoption : gssapikeytab",
"genericruleoption : gssapiservicename",
"genericruleoption : hostidoption",
"genericruleoption : rule_internal_logoption",
"genericruleoption : libwrap",
"genericruleoption : log",
"genericruleoption : pamservicename",
"genericruleoption : redirect",
"genericruleoption : socketoption",
"genericruleoption : timeout",
"genericruleoption : user",
"ldapoption : ldapattribute",
"ldapoption : ldapattribute_ad",
"ldapoption : ldapattribute_ad_hex",
"ldapoption : ldapattribute_hex",
"ldapoption : ldapauto",
"ldapoption : lbasedn",
"ldapoption : lbasedn_hex",
"ldapoption : lbasedn_hex_all",
"ldapoption : ldapcertcheck",
"ldapoption : ldapcertfile",
"ldapoption : ldapcertpath",
"ldapoption : ldapdebug",
"ldapoption : ldapdepth",
"ldapoption : ldapdomain",
"ldapoption : ldapfilter",
"ldapoption : ldapfilter_ad",
"ldapoption : ldapfilter_ad_hex",
"ldapoption : ldapfilter_hex",
"ldapoption : ldapkeeprealm",
"ldapoption : ldapkeytab",
"ldapoption : ldapport",
"ldapoption : ldapportssl",
"ldapoption : ldapssl",
"ldapoption : lgroup",
"ldapoption : lgroup_hex",
"ldapoption : lgroup_hex_all",
"ldapoption : lserver",
"ldapoption : lurl",
"ldapdebug : LDAPDEBUG ':' NUMBER",
"ldapdebug : LDAPDEBUG ':' '-' NUMBER",
"ldapdomain : LDAPDOMAIN ':' LDAP_DOMAIN",
"ldapdepth : LDAPDEPTH ':' NUMBER",
"ldapcertfile : LDAPCERTFILE ':' LDAP_CERTFILE",
"ldapcertpath : LDAPCERTPATH ':' LDAP_CERTPATH",
"lurl : LDAPURL ':' LDAP_URL",
"lbasedn : LDAPBASEDN ':' LDAP_BASEDN",
"lbasedn_hex : LDAPBASEDN_HEX ':' LDAP_BASEDN",
"lbasedn_hex_all : LDAPBASEDN_HEX_ALL ':' LDAP_BASEDN",
"ldapport : LDAPPORT ':' NUMBER",
"ldapportssl : LDAPPORTSSL ':' NUMBER",
"ldapssl : LDAPSSL ':' YES",
"ldapssl : LDAPSSL ':' NO",
"ldapauto : LDAPAUTO ':' YES",
"ldapauto : LDAPAUTO ':' NO",
"ldapcertcheck : LDAPCERTCHECK ':' YES",
"ldapcertcheck : LDAPCERTCHECK ':' NO",
"ldapkeeprealm : LDAPKEEPREALM ':' YES",
"ldapkeeprealm : LDAPKEEPREALM ':' NO",
"ldapfilter : LDAPFILTER ':' LDAP_FILTER",
"ldapfilter_ad : LDAPFILTER_AD ':' LDAP_FILTER",
"ldapfilter_hex : LDAPFILTER_HEX ':' LDAP_FILTER",
"ldapfilter_ad_hex : LDAPFILTER_AD_HEX ':' LDAP_FILTER",
"ldapattribute : LDAPATTRIBUTE ':' LDAP_ATTRIBUTE",
"ldapattribute_ad : LDAPATTRIBUTE_AD ':' LDAP_ATTRIBUTE",
"ldapattribute_hex : LDAPATTRIBUTE_HEX ':' LDAP_ATTRIBUTE",
"ldapattribute_ad_hex : LDAPATTRIBUTE_AD_HEX ':' LDAP_ATTRIBUTE",
"lgroup_hex : LDAPGROUP_HEX ':' LDAPGROUP_NAME",
"lgroup_hex_all : LDAPGROUP_HEX_ALL ':' LDAPGROUP_NAME",
"lgroup : LDAPGROUP ':' LDAPGROUP_NAME",
"lserver : LDAPSERVER ':' LDAPSERVER_NAME",
"ldapkeytab : LDAPKEYTAB ':' LDAPKEYTABNAME",
"clientcompatibility : CLIENTCOMPATIBILITY ':' clientcompatibilitynames",
"clientcompatibilityname : NECGSSAPI",
"clientcompatibilitynames : clientcompatibilityname",
"clientcompatibilitynames : clientcompatibilityname clientcompatibilitynames",
"verdict : VERDICT_BLOCK",
"verdict : VERDICT_PASS",
"command : COMMAND ':' commands",
"commands : commandname",
"commands : commandname commands",
"commandname : COMMAND_BIND",
"commandname : COMMAND_CONNECT",
"commandname : COMMAND_UDPASSOCIATE",
"commandname : COMMAND_BINDREPLY",
"commandname : COMMAND_UDPREPLY",
"protocol : PROTOCOL ':' protocols",
"protocols : protocolname",
"protocols : protocolname protocols",
"protocolname : PROTOCOL_TCP",
"protocolname : PROTOCOL_UDP",
"fromto : srcaddress dstaddress",
"hostid_fromto : hostid_srcaddress dstaddress",
"redirect : REDIRECT rdr_fromaddress rdr_toaddress",
"redirect : REDIRECT rdr_fromaddress",
"redirect : REDIRECT rdr_toaddress",
"sessionoption : sessionmax",
"sessionoption : sessionthrottle",
"sessionoption : sessionstate",
"sockssessionoption : sessionoption",
"crulesessionoption : sessioninheritable",
"crulesessionoption : sessionoption",
"sessioninheritable : SESSION_INHERITABLE ':' YES",
"sessioninheritable : SESSION_INHERITABLE ':' NO",
"sessionmax : SESSIONMAX ':' NUMBER",
"sessionthrottle : SESSIONTHROTTLE ':' NUMBER '/' NUMBER",
"sessionstate : sessionstate_key",
"sessionstate : sessionstate_keyinfo",
"sessionstate : sessionstate_throttle",
"sessionstate : sessionstate_max",
"sessionstate_key : SESSIONSTATE_KEY ':' STATEKEY",
"$$24 :",
"sessionstate_keyinfo : SESSIONSTATE_KEY '.' $$24 hostindex",
"sessionstate_max : SESSIONSTATE_MAX ':' NUMBER",
"sessionstate_throttle : SESSIONSTATE_THROTTLE ':' NUMBER '/' NUMBER",
"bandwidth : BANDWIDTH ':' NUMBER",
"log : RULE_LOG ':' logs",
"logname : RULE_LOG_CONNECT",
"logname : RULE_LOG_DATA",
"logname : RULE_LOG_DISCONNECT",
"logname : RULE_LOG_ERROR",
"logname : RULE_LOG_IOOPERATION",
"logname : RULE_LOG_TCPINFO",
"logs : logname",
"logs : logname logs",
"pamservicename : PAMSERVICENAME ':' SERVICENAME",
"bsdauthstylename : BSDAUTHSTYLE ':' BSDAUTHSTYLENAME",
"gssapiservicename : GSSAPISERVICE ':' GSSAPISERVICENAME",
"gssapikeytab : GSSAPIKEYTAB ':' GSSAPIKEYTABNAME",
"gssapienctype : GSSAPIENCTYPE ':' gssapienctypes",
"gssapienctypename : GSSAPIENC_ANY",
"gssapienctypename : GSSAPIENC_CLEAR",
"gssapienctypename : GSSAPIENC_INTEGRITY",
"gssapienctypename : GSSAPIENC_CONFIDENTIALITY",
"gssapienctypename : GSSAPIENC_PERMESSAGE",
"gssapienctypes : gssapienctypename",
"gssapienctypes : gssapienctypename gssapienctypes",
"bounce : BOUNCE bounceto ':' bouncetoaddress",
"libwrap : LIBWRAPSTART ':' LINE",
"srcaddress : from ':' address",
"hostid_srcaddress : from ':' address_without_port",
"dstaddress : to ':' address",
"rdr_fromaddress : rdr_from ':' address",
"rdr_toaddress : rdr_to ':' address",
"gateway : via ':' gwaddress",
"routeoption : routemethod",
"routeoption : command",
"routeoption : clientcompatibility",
"routeoption : extension",
"routeoption : protocol",
"routeoption : gssapiservicename",
"routeoption : gssapikeytab",
"routeoption : gssapienctype",
"routeoption : proxyprotocol",
"routeoption : REDIRECT rdr_fromaddress",
"routeoption : socketoption",
"routeoptions :",
"routeoptions : routeoption routeoptions",
"routemethod : METHOD ':' socksmethods",
"from : FROM",
"to : TO",
"rdr_from : FROM",
"rdr_to : TO",
"bounceto : TO",
"via : VIA",
"externaladdress : ipv4",
"externaladdress : ipv6",
"externaladdress : domain",
"externaladdress : ifname",
"address_without_port : ipaddress",
"address_without_port : domain",
"address_without_port : ifname",
"address : address_without_port port",
"ipaddress : ipv4 '/' netmask_v4",
"ipaddress : ipv4",
"ipaddress : ipv6 '/' netmask_v6",
"ipaddress : ipv6",
"ipaddress : ipvany '/' netmask_vany",
"ipaddress : ipvany",
"gwaddress : ipaddress gwport",
"gwaddress : domain gwport",
"gwaddress : ifname",
"gwaddress : url",
"bouncetoaddress : ipaddress gwport",
"bouncetoaddress : domain gwport",
"ipv4 : IPV4",
"netmask_v4 : NUMBER",
"netmask_v4 : IPV4",
"ipv6 : IPV6",
"netmask_v6 : NUMBER",
"ipvany : IPVANY",
"netmask_vany : NUMBER",
"domain : DOMAINNAME",
"ifname : IFNAME",
"url : URL",
"port :",
"port : PORT ':' portnumber",
"port : PORT portoperator portnumber",
"port : PORT portrange",
"gwport :",
"gwport : PORT portoperator portnumber",
"portnumber : portservice",
"portnumber : portstart",
"portrange : portstart '-' portend",
"portstart : NUMBER",
"portend : NUMBER",
"portservice : SERVICENAME",
"portoperator : OPERATOR",
"udpportrange : UDPPORTRANGE ':' udpportrange_start '-' udpportrange_end",
"udpportrange_start : NUMBER",
"udpportrange_end : NUMBER",
"number : NUMBER",
"numbers : number",
"numbers : number numbers",

};
#endif

int      yydebug;
int      yynerrs;

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;
/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 3084 "config_parse.y"

#define INTERACTIVE      0

extern FILE *yyin;

int lex_dorestart; /* global for Lex. */

int
parseconfig(filename)
   const char *filename;
{
   const char *function = "parseconfig()";
   struct stat statbuf;
   int haveconfig;

#if SOCKS_CLIENT /* assume server admin can set things up correctly himself. */
   parseclientenv(&haveconfig);

   if (haveconfig)
      return 0;

#else /* !SOCKS_CLIENT */
   SASSERTX(pidismainmother(sockscf.state.pid));

   if (sockscf.state.inited)
      /* in case we need something special to (re)open config-file. */
      sockdiops_priv(SOCKD_PRIV_PRIVILEGED, PRIV_ON);
#endif /* !SOCKS_CLIENT */

   yyin = fopen(filename, "r");

#if !SOCKS_CLIENT
   if (sockscf.state.inited)
      sockdiops_priv(SOCKD_PRIV_PRIVILEGED, PRIV_OFF);
#endif /* SERVER */

   if (yyin == NULL
   ||  (stat(filename, &statbuf) == 0 && statbuf.st_size == 0)) {
      if (yyin == NULL)
         slog(sockscf.state.inited ? LOG_WARNING : LOG_ERR,
              "%s: could not open config file %s", function, filename);
      else
         slog((sockscf.state.inited || SOCKS_CLIENT) ? LOG_WARNING : LOG_ERR,
              "%s: config file %s is empty.  Not parsing", function, filename);

#if SOCKS_CLIENT

      if (yyin == NULL) {
         if (sockscf.option.directfallback)
            slog(LOG_DEBUG,
                 "%s: no %s, but direct fallback enabled, continuing",
                 function, filename);
         else
            exit(0);
      }
      else {
         slog(LOG_DEBUG, "%s: empty %s, assuming direct fallback wanted",
              function, filename);

         sockscf.option.directfallback = 1;
      }

      SASSERTX(sockscf.option.directfallback == 1);
#else /* !SOCKS_CLIENT */

      if (!sockscf.state.inited)
         sockdiopsexit(EXIT_FAILURE);

      /*
       * Might possibly continue with old config.
       */

#endif /* !SOCKS_CLIENT */

      haveconfig = 0;
   }
   else {
#if YYDEBUG
      yydebug       = 0;
#endif /* YYDEBUG */

      yylineno      = 1;
      errno         = 0;   /* don't report old errors in yyparse(). */
      haveconfig    = 1;

      /*
       * Special and delayed as long as we can, till immediately before
       * parsing new config.
       * Want to keep a backup of old ones until we know there were no
       * errors adding new logfiles.
       */

#if !SOCKS_CLIENT
      old_log              = sockscf.log;
      old_errlog           = sockscf.errlog;
#endif /* !SOCKS_CLIENT */

      failed_to_add_errlog = failed_to_add_log = 0;

      slog(LOG_DEBUG, "%s: parsing config in file %s", function, filename);

      bzero(&sockscf.log,    sizeof(sockscf.log));
      bzero(&sockscf.errlog, sizeof(sockscf.errlog));

      lex_dorestart = 1;

      parsingconfig = 1;

#if SOCKSLIBRARY_DYNAMIC
      socks_markasnative("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

      yyparse();

#if SOCKSLIBRARY_DYNAMIC
      socks_markasnormal("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

      parsingconfig = 0;

#if !SOCKS_CLIENT
      CMDLINE_OVERRIDE(&sockscf.initial.cmdline, &sockscf.option);

#if !HAVE_PRIVILEGES
      if (!sockscf.state.inited) {
         /*
          * first time.
          */
         if (sockscf.uid.privileged_isset && !sockscf.option.verifyonly) {
            /*
             * If we created any logfiles (rather than just opened already
             * existing ones), they will have been created with the euid/egid
             * we are started with.  If logfiles created by that euid/egid are
             * not writable by our configured privileged userid (if any), it
             * means that upon SIGHUP we will be unable to re-open our own
             * logfiles.  We therefor check whether the logfile(s) were created
             * by ourselves, and if so, make sure they have the right owner.
             */
            logtype_t *logv[] = { &sockscf.log, &sockscf.errlog };
            size_t i;

            for (i = 0; i < ELEMENTS(logv); ++i) {
               size_t fi;

               for (fi = 0; fi < logv[i]->filenoc; ++fi) {
                  if (logv[i]->createdv[fi]) {
                     slog(LOG_DEBUG,
                          "%s: chown(2)-ing created logfile %s to %lu/%lu",
                          function,
                          logv[i]->fnamev[fi],
                          (unsigned long)sockscf.uid.privileged_uid,
                          (unsigned long)sockscf.uid.privileged_gid);

                     if (fchown(logv[i]->filenov[fi],
                                (unsigned long)sockscf.uid.privileged_uid,
                                (unsigned long)sockscf.uid.privileged_gid) != 0)
                        serr("%s: could not fchown(2) created logfile %s to "
                             "privileged uid/gid %lu/%lu.  This means that "
                             "upon SIGHUP, we would not be unable to re-open "
                             "our own logfiles.  This should not happen",
                             function,
                             logv[i]->fnamev[fi],
                             (unsigned long)sockscf.uid.privileged_uid,
                             (unsigned long)sockscf.uid.privileged_gid);
                  }
               }
            }
         }
      }
#endif /* !HAVE_PRIVILEGES */

      if (configure_privileges() != 0) {
         if (sockscf.state.inited) {
            swarn("%s: could not reinitialize privileges after SIGHUP.  "
                  "Will continue without privileges",
                  function);

            sockscf.state.haveprivs = 0;
         }
         else
            serr("%s: could not configure privileges", function);
      }
#endif /* !SOCKS_CLIENT */
   }

   if (yyin != NULL)
      fclose(yyin);

   errno = 0;
   return haveconfig ? 0 : -1;
}

static int
ipaddr_requires_netmask(context, objecttype)
   const addresscontext_t context;
   const objecttype_t objecttype;
{

   switch (objecttype) {
      case object_crule:
#if HAVE_SOCKS_RULES

         return 1;

#else /* !HAVE_SOCKS_RULES */

         switch (context) {
            case from:
               return 1;

            case to:
               return 0; /* address we accept clients on. */

            case bounce:
               return 0; /* address we connect to.        */

            default:
               SERRX(context);
         }
#endif /* !HAVE_SOCKS_RULES */


#if HAVE_SOCKS_HOSTID
      case object_hrule:
         return 1;
#endif /* HAVE_SOCKS_HOSTID */

#if HAVE_SOCKS_RULES
      case object_srule:
         return 1;
#endif /* HAVE_SOCKS_RULES */

      case object_route:
      case object_monitor:
         return 1;

      default:
         SERRX(objecttype);
   }


   /* NOTREACHED */
   return 0;
}


static void
addnumber(numberc, numberv, number)
   size_t *numberc;
   long long *numberv[];
   const long long number;
{
   const char *function = "addnumber()";

   if ((*numberv = realloc(*numberv, sizeof(**numberv) * ((*numberc) + 1)))
   == NULL)
      yyerror("%s: could not allocate %lu bytes of memory for adding "
              "number %lld",
              function, (unsigned long)(sizeof(**numberv) * ((*numberc) + 1)),
              number);

   (*numberv)[(*numberc)++] = number;
}


static void
addrinit(addr, _netmask_required)
   ruleaddr_t *addr;
   const int _netmask_required;
{

   atype            = &addr->atype;

   ipv4             = &addr->addr.ipv4.ip;
   netmask_v4       = &addr->addr.ipv4.mask;

   ipv6             = &addr->addr.ipv6.ip;
   netmask_v6       = &addr->addr.ipv6.maskbits;
   scopeid_v6       = &addr->addr.ipv6.scopeid;

   ipvany           = &addr->addr.ipvany.ip;
   netmask_vany     = &addr->addr.ipvany.mask;

   if (!_netmask_required) {
      netmask_v4->s_addr   = htonl(IPV4_FULLNETMASK);
      *netmask_v6          = IPV6_NETMASKBITS;
      netmask_vany->s_addr = htonl(IPV4_FULLNETMASK);
   }

   domain           = addr->addr.domain;
   ifname           = addr->addr.ifname;

   port_tcp         = &addr->port.tcp;
   port_udp         = &addr->port.udp;
   operator         = &addr->operator;

   netmask_required = _netmask_required;
   ruleaddr         = addr;
}

static void
gwaddrinit(addr)
   sockshost_t *addr;
{
   static enum operator_t operatormem;

   netmask_required = 0;

   atype            = &addr->atype;

   ipv4             = &addr->addr.ipv4;
   ipv6             = &addr->addr.ipv6.ip;
   domain           = addr->addr.domain;
   ifname           = addr->addr.ifname;
   url              = addr->addr.urlname;

   port_tcp         = &addr->port;
   port_udp         = &addr->port;
   operator         = &operatormem; /* no operator in gwaddr and not used. */
}

static void
routeinit(route)
   route_t *route;
{
   bzero(route, sizeof(*route));

   state               = &route->gw.state;
   extension           = &state->extension;

   cmethodv            = state->cmethodv;
   cmethodc            = &state->cmethodc;
   smethodv            = state->smethodv;
   smethodc            = &state->smethodc;

#if HAVE_GSSAPI
   gssapiservicename = state->gssapiservicename;
   gssapikeytab      = state->gssapikeytab;
   gssapiencryption  = &state->gssapiencryption;
#endif /* HAVE_GSSAPI */

#if !SOCKS_CLIENT && HAVE_LDAP
   ldap              = &state->ldap;
#endif /* !SOCKS_CLIENT && HAVE_LDAP*/

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   src.atype = SOCKS_ADDR_IPV4;
   dst.atype = SOCKS_ADDR_IPV4;

   bzero(&gw, sizeof(gw));
   bzero(&rdr_from, sizeof(rdr_from));
   bzero(&hostid, sizeof(hostid));
}


#if SOCKS_CLIENT
static void
parseclientenv(haveproxyserver)
   int *haveproxyserver;
{
   const char *function = "parseclientenv()";
   const char *fprintf_error = "could not write to tmpfile used to hold "
                               "settings set in environment for parsing";
   size_t i;
   FILE *fp;
   char *p, rdr_from[512], extrarouteinfo[sizeof(rdr_from) + sizeof("\n")],
        gw[MAXSOCKSHOSTLEN + sizeof(" port = 65535")];
   int fd;


#if 1

#if SOCKS_CLIENT
   p = "yaccenv-client-XXXXXX";
#else /* !SOCKS_CLIENT */
   p = "yaccenv-server-XXXXXX";
#endif /* !SOCKS_CLIENT */

   if ((fd = socks_mklock(p, NULL, 0)) == -1)
      yyerror("socks_mklock() failed to create tmpfile using base %s", p);

#else /* for debugging file-generation problems. */
   if ((fd = open("/tmp/dante-envfile",
                  O_CREAT | O_TRUNC | O_RDWR,
                  S_IRUSR | S_IWUSR)) == -1)
      serr("%s: could not open file", function);
#endif

   if ((fp = fdopen(fd, "r+")) == NULL)
      serr("%s: fdopen(fd %d) failed", function, fd);

   if ((p = socks_getenv(ENV_SOCKS_LOGOUTPUT, dontcare)) != NULL && *p != NUL)
      if (fprintf(fp, "logoutput: %s\n", p) == -1)
         serr("%s: %s", function, fprintf_error);

   if ((p = socks_getenv(ENV_SOCKS_ERRLOGOUTPUT, dontcare)) != NULL
   && *p != NUL)
      if (fprintf(fp, "errorlog: %s\n", p) == -1)
         serr("%s: %s", function, fprintf_error);

   if ((p = socks_getenv(ENV_SOCKS_DEBUG, dontcare)) != NULL && *p != NUL)
      if (fprintf(fp, "debug: %s\n", p) == -1)
         serr("%s: %s", function, fprintf_error);

   *rdr_from = NUL;
   if ((p = socks_getenv(ENV_SOCKS_REDIRECT_FROM, dontcare)) != NULL
   && *p != NUL) {
      const char *prefix = "redirect from";

      if (strlen(prefix) + strlen(p) + 1 > sizeof(rdr_from))
         serr("%s: %s value is too long.  Max length is %lu",
              function,
              ENV_SOCKS_REDIRECT_FROM,
              (unsigned long)sizeof(rdr_from) - (strlen(prefix) + 1));

      snprintf(rdr_from, sizeof(rdr_from), "%s: %s\n", prefix, p);
   }

   snprintf(extrarouteinfo, sizeof(extrarouteinfo),
            "%s", rdr_from);

   /*
    * Check if there is a proxy server configured in the environment.
    * Initially assume there is none.
    */

   *haveproxyserver = 0;

   i = 1;
   while (1) {
      /* 640 routes should be enough for anyone. */
      char name[sizeof(ENV_SOCKS_ROUTE_) + sizeof("640")];

      snprintf(name, sizeof(name), "%s%lu", ENV_SOCKS_ROUTE_, (unsigned long)i);

      if ((p = socks_getenv(name, dontcare)) == NULL)
         break;

      if (*p != NUL) {
         if (fprintf(fp, "route { %s }\n", p) == -1)
            serr("%s: %s", function, fprintf_error);

         *haveproxyserver = 1;
      }

      ++i;
   }

   if ((p = socks_getenv(ENV_SOCKS4_SERVER, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         proxyprotocol: socks_v4\n"
"         %s"
"}\n",            serverstring2gwstring(p, PROXY_SOCKS_V4, gw, sizeof(gw)),
                  extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_SOCKS5_SERVER, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         proxyprotocol: socks_v5\n"
"         %s"
"}\n",            serverstring2gwstring(p, PROXY_SOCKS_V5, gw, sizeof(gw)),
                  extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_SOCKS_SERVER, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         %s"
"}\n",            serverstring2gwstring(p, PROXY_SOCKS_V5, gw, sizeof(gw)),
                  extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_HTTP_PROXY, dontcare)) != NULL && *p != NUL) {
      struct sockaddr_storage sa;
      int gaierr;
      char emsg[512];

      if (urlstring2sockaddr(p, &sa, &gaierr, emsg, sizeof(emsg)) == NULL)
         serr("%s: could not convert to %s to an Internet address",
              function, p);

      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s port = %d\n"
"         proxyprotocol: http_v1.0\n"
"         %s"
"}\n",
                  sockaddr2string2(&sa, 0, NULL, 0),
                  ntohs(GET_SOCKADDRPORT(&sa)),
                  extrarouteinfo)
      == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }

   if ((p = socks_getenv(ENV_UPNP_IGD, dontcare)) != NULL && *p != NUL) {
      if (fprintf(fp,
"route {\n"
"         from: 0.0.0.0/0 to: 0.0.0.0/0 via: %s\n"
"         proxyprotocol: upnp\n"
"         %s"
"}\n",            p, extrarouteinfo) == -1)
         serr("%s: %s", function, fprintf_error);

      *haveproxyserver = 1;
   }


   /*
    * End of possible settings we want to parse with yacc/lex.
    */

   if (fseek(fp, 0, SEEK_SET) != 0)
      yyerror("fseek(3) on tmpfile used to hold environment-settings failed");

   yyin = fp;

   lex_dorestart             = 1;
   parsingconfig             = 1;
   p                         = sockscf.option.configfile;
   sockscf.option.configfile = "<generated socks.conf>";

#if SOCKSLIBRARY_DYNAMIC
   socks_markasnative("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

   yyparse();

#if SOCKSLIBRARY_DYNAMIC
   socks_markasnormal("*");
#endif /* SOCKSLIBRARY_DYNAMIC */

   sockscf.option.configfile = p;
   parsingconfig             = 0;

   fclose(fp);

   if (socks_getenv(ENV_SOCKS_AUTOADD_LANROUTES, isfalse) == NULL) {
      /*
       * assume it's good to add direct routes for the lan also.
       */
      struct ifaddrs *ifap;

      slog(LOG_DEBUG, "%s: auto-adding direct routes for lan ...", function);

      if (getifaddrs(&ifap) == 0) {
         command_t commands;
         protocol_t protocols;
         struct ifaddrs *iface;

         bzero(&commands, sizeof(commands));
         bzero(&protocols, sizeof(protocols));

         protocols.tcp = 1;
         protocols.udp = 1;

         commands.connect      = 1;
         commands.udpassociate = 1;

         for (iface = ifap; iface != NULL; iface = iface->ifa_next)
            if (iface->ifa_addr            != NULL
            &&  iface->ifa_addr->sa_family == AF_INET) {
               if (iface->ifa_netmask == NULL) {
                  swarn("interface %s missing netmask, skipping",
                        iface->ifa_name);
                  continue;
               }

               socks_autoadd_directroute(&commands,
                                         &protocols,
                                         TOCSS(iface->ifa_addr),
                                         TOCSS(iface->ifa_netmask));
            }

         freeifaddrs(ifap);
      }
   }
   else
      slog(LOG_DEBUG, "%s: not auto-adding direct routes for lan", function);
}

static char *
serverstring2gwstring(serverstring, version, gw, gwsize)
   const char *serverstring;
   const int version;
   char *gw;
   const size_t gwsize;
{
   const char *function = "serverstring2gwstring()";
   char *sep, emsg[256];

   if (version != PROXY_SOCKS_V4 && version != PROXY_SOCKS_V5)
      return gw; /* should be in desired format already. */

   if (strlen(serverstring) >= gwsize)
      serrx("%s: value of proxyserver (%s) set in environment is too long.  "
            "Max length is %lu",
            function, serverstring, (unsigned long)(gwsize - 1));

   if ((sep = strrchr(serverstring, ':')) != NULL && *(sep + 1) != NUL) {
      long port;

      if ((port = string2portnumber(sep + 1, emsg, sizeof(emsg))) == -1)
         yyerrorx("%s: %s", function, emsg);

      memcpy(gw, serverstring, sep - serverstring);
      snprintf(&gw[sep - serverstring],
               gwsize - (sep - serverstring),
               " port = %u",
               (in_port_t)port);
   }
   else {
      char visbuf[256];

      yyerrorx("%s: could not find portnumber in %s serverstring \"%s\"",
               function,
               proxyprotocol2string(version),
               str2vis(sep == NULL ? serverstring : sep,
                       strlen(sep == NULL ? serverstring : sep),
                       visbuf,
                       sizeof(visbuf)));
   }

   return gw;
}

#else /* !SOCKS_CLIENT */

static void
pre_addrule(rule)
   rule_t *rule;
{

   rule->src   = src;
   rule->dst   = dst;

#if HAVE_SOCKS_HOSTID
   rule->hostid      = hostid;
#endif /* HAVE_SOCKS_HOSTID */

   rule->rdr_from    = rdr_from;
   rule->rdr_to      = rdr_to;

   if (session_isset) {
      if ((rule->ss = malloc(sizeof(*rule->ss))) == NULL)
         yyerror("failed to malloc(3) %lu bytes for session memory",
                 (unsigned long)sizeof(*rule->ss));

      *rule->ss = ss;
   }

   if (bw_isset) {
      if ((rule->bw = malloc(sizeof(*rule->bw))) == NULL)
         yyerror("failed to malloc(3) %lu bytes for bw memory",
                 (unsigned long)sizeof(*rule->bw));

      *rule->bw = bw;
   }
}


static void
post_addrule(void)
{

   timeout = &sockscf.timeout; /* default is global timeout, unless in a rule */
}

static void
ruleinit(rule)
   rule_t *rule;
{
   bzero(rule, sizeof(*rule));

   rule->linenumber  = yylineno;

#if HAVE_SOCKS_HOSTID
   rule->hostindex          = DEFAULT_HOSTINDEX;
   hostindex                = &rule->hostindex;

   rule->hostidoption_isset = 0;
   hostidoption_isset       = &rule->hostidoption_isset;
#endif /* HAVE_SOCKS_HOSTID */

   state          = &rule->state;

   cmethodv       = state->cmethodv;
   cmethodc       = &state->cmethodc;

   smethodv       = state->smethodv;
   smethodc       = &state->smethodc;

   /*
    * default values: same as global.
    */

   timeout       = &rule->timeout;
   *timeout      = sockscf.timeout;

#if HAVE_GSSAPI
   gssapiservicename = state->gssapiservicename;
   gssapikeytab      = state->gssapikeytab;
   gssapiencryption  = &state->gssapiencryption;
#endif /* HAVE_GSSAPI */

#if HAVE_LDAP
   ldap              = &state->ldap;
#endif

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   bzero(&hostid, sizeof(hostid));

   bzero(&rdr_from, sizeof(rdr_from));
   bzero(&rdr_to, sizeof(rdr_to));

#if BAREFOOTD
   bzero(&bounceto, sizeof(bounceto));
#endif /* BAREFOOTD */

   rule->bw_isinheritable   = rule->ss_isinheritable = 1;

   bzero(&ss, sizeof(ss));
   bzero(&bw, sizeof(bw));

   bw_isset = session_isset = 0;
   bw.type  = SHMEM_BW;
   ss.type  = SHMEM_SS;
}

void
alarminit(void)
{
    static int alarmside_mem;

   alarmside  = &alarmside_mem;
   *alarmside = 0;
}

static void
monitorinit(monitor)
   monitor_t *monitor;
{
   static int alarmside_mem;

   alarmside = &alarmside_mem;

   bzero(monitor, sizeof(*monitor));

   monitor->linenumber = yylineno;

   state                       = &monitor->state;

#if HAVE_SOCKS_HOSTID
   monitor->hostindex          = DEFAULT_HOSTINDEX;
   hostindex                   = &monitor->hostindex;

   monitor->hostidoption_isset = 0;
   hostidoption_isset          = &monitor->hostidoption_isset;
#endif /* HAVE_SOCKS_HOSTID */

   bzero(&src, sizeof(src));
   bzero(&dst, sizeof(dst));
   bzero(&hostid, sizeof(hostid));

   if ((monitor->mstats = malloc(sizeof(*monitor->mstats))) == NULL)
      yyerror("failed to malloc(3) %lu bytes for monitor stats memory",
              (unsigned long)sizeof(*monitor->mstats));
   else
      bzero(monitor->mstats, sizeof(*monitor->mstats));

   monitor->mstats->type = SHMEM_MONITOR;
}

static void
pre_addmonitor(monitor)
   monitor_t *monitor;
{
   monitor->src    = src;
   monitor->dst    = dst;

#if HAVE_SOCKS_HOSTID
   monitor->hostid = hostid;
#endif /* HAVE_SOCKS_HOSTID */
}

static int
configure_privileges(void)
{
   const char *function = "configure_privileges()";
   static int isfirsttime = 1;

   if (sockscf.option.verifyonly)
      return 0;

#if !HAVE_PRIVILEGES
   uid_t uid; /* for debugging. */
   gid_t gid; /* for debugging. */

   SASSERTX(sockscf.state.euid == (uid = geteuid()));
   SASSERTX(sockscf.state.egid == (gid = getegid()));

   /*
    * Check all configured uids/gids work.
    */

   checkugid(&sockscf.uid.privileged_uid,
             &sockscf.uid.privileged_gid,
             &sockscf.uid.privileged_isset,
             "privileged");

   checkugid(&sockscf.uid.unprivileged_uid,
             &sockscf.uid.unprivileged_gid,
             &sockscf.uid.unprivileged_isset,
             "unprivileged");

#if HAVE_LIBWRAP
   if (!sockscf.uid.libwrap_isset
   &&  sockscf.uid.unprivileged_isset) {
      sockscf.uid.libwrap_uid   = sockscf.uid.unprivileged_uid;
      sockscf.uid.libwrap_gid   = sockscf.uid.unprivileged_gid;
      sockscf.uid.libwrap_isset = sockscf.uid.unprivileged_isset;
   }
   else
      checkugid(&sockscf.uid.libwrap_uid,
                &sockscf.uid.libwrap_gid,
                &sockscf.uid.libwrap_isset,
                "libwrap");
#endif /* HAVE_LIBWRAP */

   SASSERTX(sockscf.state.euid == (uid = geteuid()));
   SASSERTX(sockscf.state.egid == (gid = getegid()));

#endif /* !HAVE_PRIVILEGES */

   if (isfirsttime) {
      if (sockdiops_initprivs() != 0) {
         slog(HAVE_PRIVILEGES ? LOG_INFO : LOG_WARNING,
              "%s: could not initialize privileges (%s)%s",
              function,
              strerror(errno),
              geteuid() == 0 ?
                   "" : ".  Usually we need to be started by root if "
                        "special privileges are to be available");

#if HAVE_PRIVILEGES
         /*
          * assume failure in this case is not fatal; some privileges will
          * not be available to us, and perhaps that is the intention too.
          */
         return 0;

#else
         return -1;
#endif /* !HAVE_PRIVILEGES */
      }

      isfirsttime = 0;
   }

   return 0;
}

static int
checkugid(uid, gid, isset, type)
   uid_t *uid;
   gid_t *gid;
   unsigned char *isset;
   const char *type;
{
   const char *function = "checkugid()";

   SASSERTX(sockscf.state.euid == geteuid());
   SASSERTX(sockscf.state.egid == getegid());

   if (sockscf.option.verifyonly)
      return 0;

   if (!(*isset)) {
      *uid   = sockscf.state.euid;
      *gid   = sockscf.state.egid;
      *isset = 1;

      return 0;
   }

   if (*uid != sockscf.state.euid) {
      if (seteuid(*uid) != 0) {
         swarn("%s: could not seteuid(2) to %s uid %lu",
               function, type, (unsigned long)*uid);

         return -1;
      }

      (void)seteuid(0);

      if (seteuid(sockscf.state.euid) != 0) {
         swarn("%s: could not revert to euid %lu from euid %lu",
               function,
               (unsigned long)sockscf.state.euid,
               (unsigned long)geteuid());
         SWARN(0);

         sockscf.state.euid = geteuid();
         return -1;
      }
   }

   if (*gid != sockscf.state.egid) {
      (void)seteuid(0);

      if (setegid(*gid) != 0) {
         swarn("%s: could not setegid(2) to %s gid %lu",
               function, type, (unsigned long)*gid);

         return -1;
      }

      (void)seteuid(0);

      if (setegid(sockscf.state.egid) != 0) {
         swarn("%s: could not revert to egid %lu from euid %lu",
               function,
               (unsigned long)sockscf.state.egid,
               (unsigned long)geteuid());
         SWARN(0);

         sockscf.state.egid = getegid();
         return -1;
      }

      if (seteuid(sockscf.state.euid) != 0) {
         swarn("%s: could not revert to euid %lu from euid %lu",
               function,
               (unsigned long)sockscf.state.euid,
               (unsigned long)geteuid());
         SWARN(0);

         sockscf.state.euid = geteuid();
         return -1;
      }
   }

   SASSERTX(sockscf.state.euid == geteuid());
   SASSERTX(sockscf.state.egid == getegid());

   return 0;
}

#endif /* !SOCKS_CLIENT */
#line 3561 "config_parse.c"

#if YYDEBUG
#include <stdio.h>		/* needed for printf */
#endif

#include <stdlib.h>	/* needed for malloc, etc */
#include <string.h>	/* needed for memset */

/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = (int) (data->s_mark - data->s_base);
    newss = (short *)realloc(data->s_base, newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base = newss;
    data->s_mark = newss + i;

    newvs = (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 1:
#line 619 "config_parse.y"
	{
#if !SOCKS_CLIENT
      extension = &sockscf.extension;
#endif /* !SOCKS_CLIENT*/
   }
break;
case 4:
#line 627 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 11:
#line 638 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 40:
#line 668 "config_parse.y"
	{
      if (!addedsocketoption(&sockscf.socketoptionc,
                             &sockscf.socketoptionv,
                             &socketopt))
         yywarn("could not add socket option");
   }
break;
case 42:
#line 677 "config_parse.y"
	{
#if !SOCKS_CLIENT
                                tcpoptions = &logspecial->protocol.tcp.disabled;
#endif /* !SOCKS_CLIENT */
          }
break;
case 44:
#line 682 "config_parse.y"
	{
#if !SOCKS_CLIENT
                                tcpoptions = &logspecial->protocol.tcp.enabled;
#endif /* !SOCKS_CLIENT */
          }
break;
case 46:
#line 690 "config_parse.y"
	{
#if !SOCKS_CLIENT

      logspecial = &sockscf.internal.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 48:
#line 700 "config_parse.y"
	{
#if !SOCKS_CLIENT

      logspecial = &sockscf.external.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 50:
#line 710 "config_parse.y"
	{
#if !SOCKS_CLIENT

      logspecial = &rule.internal.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 52:
#line 720 "config_parse.y"
	{
#if !SOCKS_CLIENT

      logspecial = &rule.external.log;

#endif /* !SOCKS_CLIENT */

   }
break;
case 54:
#line 731 "config_parse.y"
	{
#if !SOCKS_CLIENT
   SASSERTX(yystack.l_mark[0].number >= 0);
   SASSERTX(yystack.l_mark[0].number < MAXLOGLEVELS);

   cloglevel = yystack.l_mark[0].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 57:
#line 745 "config_parse.y"
	{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, ecn);
#endif /* !SOCKS_CLIENT */
   }
break;
case 58:
#line 752 "config_parse.y"
	{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, sack);
#endif /* !SOCKS_CLIENT */
   }
break;
case 59:
#line 759 "config_parse.y"
	{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, timestamps);
#endif /* !SOCKS_CLIENT */
   }
break;
case 60:
#line 766 "config_parse.y"
	{
#if !SOCKS_CLIENT
   SET_TCPOPTION(tcpoptions, cloglevel, wscale);
#endif /* !SOCKS_CLIENT */
   }
break;
case 63:
#line 779 "config_parse.y"
	{
#if !SOCKS_CLIENT

   if (yystack.l_mark[0].error.valuev == NULL)
      yywarnx("unknown error symbol specified");
   else {
      size_t *ec, ec_max, i;
      int *ev;

      switch (yystack.l_mark[0].error.valuetype) {
         case VALUETYPE_ERRNO:
            ev     = logspecial->errno_loglevelv[cloglevel];
            ec     = &logspecial->errno_loglevelc[cloglevel];
            ec_max = ELEMENTS(logspecial->errno_loglevelv[cloglevel]);
            break;

         case VALUETYPE_GAIERR:
            ev     = logspecial->gaierr_loglevelv[cloglevel];
            ec     = &logspecial->gaierr_loglevelc[cloglevel];
            ec_max = ELEMENTS(logspecial->gaierr_loglevelv[cloglevel]);
            break;

         default:
            SERRX(yystack.l_mark[0].error.valuetype);
      }

      for (i = 0; yystack.l_mark[0].error.valuev[i] != 0; ++i) {
         /*
          * If the value is already set in the array, e.g. because some
          * errno-symbols have the same values, ignore this value.
          */
         size_t j;

         for (j = 0; j < *ec; ++j) {
            if (ev[j] == yystack.l_mark[0].error.valuev[i])
               break;
         }

         if (j < *ec)
            continue; /* error-value already set in array. */

         SASSERTX(*ec < ec_max);

         ev[(*ec)] = yystack.l_mark[0].error.valuev[i];
         ++(*ec);
      }
   }
#endif /* !SOCKS_CLIENT */
   }
break;
case 68:
#line 837 "config_parse.y"
	{
      yyerrorx("given keyword \"%s\" is deprecated.  New keyword is %s.  "
               "Please see %s's manual for more information",
               yystack.l_mark[0].deprecated.oldname, yystack.l_mark[0].deprecated.newname, PRODUCT);
   }
break;
case 69:
#line 844 "config_parse.y"
	{ objecttype = object_route; }
break;
case 70:
#line 845 "config_parse.y"
	{ routeinit(&route); }
break;
case 71:
#line 845 "config_parse.y"
	{
      route.src       = src;
      route.dst       = dst;
      route.gw.addr   = gw;

      route.rdr_from  = rdr_from;

      socks_addroute(&route, 1);
   }
break;
case 72:
#line 856 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 75:
#line 862 "config_parse.y"
	{
         state->proxyprotocol.socks_v4 = 1;
   }
break;
case 76:
#line 865 "config_parse.y"
	{
         state->proxyprotocol.socks_v5 = 1;
   }
break;
case 77:
#line 868 "config_parse.y"
	{
         state->proxyprotocol.http     = 1;
   }
break;
case 78:
#line 871 "config_parse.y"
	{
         state->proxyprotocol.upnp     = 1;
   }
break;
case 83:
#line 884 "config_parse.y"
	{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.user, yystack.l_mark[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 87:
#line 899 "config_parse.y"
	{
#if !SOCKS_CLIENT
      if (addlinkedname(&rule.group, yystack.l_mark[0].string) == NULL)
         yyerror(NOMEM);
#endif /* !SOCKS_CLIENT */
   }
break;
case 91:
#line 914 "config_parse.y"
	{
         yywarnx("we are currently considering deprecating the Dante-specific "
                 "SOCKS bind extension.  If you are using it, please let us "
                 "know on the public dante-misc@inet.no mailinglist");

         extension->bind = 1;
   }
break;
case 96:
#line 932 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ifproto->ipv4  = 1;
   }
break;
case 97:
#line 936 "config_parse.y"
	{
      ifproto->ipv6  = 1;
#endif /* SOCKS_SERVER */
   }
break;
case 98:
#line 942 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if BAREFOOTD
      yyerrorx("\"internal:\" specification is not used in %s", PRODUCT);
#endif /* BAREFOOTD */

      interfaceprotocol_t ifprotozero;

      bzero(&ifprotozero, sizeof(ifprotozero));
      if (memcmp(&ifprotozero,
                 &sockscf.internal.protocol,
                 sizeof(sockscf.internal.protocol)) == 0) {
         slog(LOG_DEBUG, "%s: no address families explicitly enabled on "
                         "internal interface.  Enabling default address "
                         "families",
                         function);

         sockscf.internal.protocol.ipv4 = sockscf.internal.protocol.ipv6 = 1;
      }

      addinternal(ruleaddr, SOCKS_TCP);
#endif /* !SOCKS_CLIENT */
   }
break;
case 99:
#line 967 "config_parse.y"
	{
#if !SOCKS_CLIENT
   static ruleaddr_t mem;
   struct servent    *service;
   serverstate_t     statemem;

   bzero(&statemem, sizeof(statemem));
   state               = &statemem;
   state->protocol.tcp = 1;

   bzero(&logspecial, sizeof(logspecial));

   bzero(&mem, sizeof(mem));
   addrinit(&mem, 0);

   /* set default port. */
   if ((service = getservbyname("socks", "tcp")) == NULL)
      *port_tcp = htons(SOCKD_PORT);
   else
      *port_tcp = (in_port_t)service->s_port;
#endif /* !SOCKS_CLIENT */
   }
break;
case 100:
#line 991 "config_parse.y"
	{
#if !SOCKS_CLIENT
      if (sockscf.internal.addrc > 0) {
         if (sockscf.state.inited) {
            /*
             * Must be running due to SIGHUP.  The internal interface requires
             * special considerations, so let the SIGHUP code deal with this
             * later when we know if the change in protocol also results in.
             * adding a new interface.
             */
            ;
         }
         else {
            log_interfaceprotocol_set_too_late(INTERNALIF);
            exit(1);
         }
      }

      ifproto = &sockscf.internal.protocol;
#endif /* !SOCKS_CLIENT */
   }
break;
case 102:
#line 1016 "config_parse.y"
	{
#if !SOCKS_CLIENT
      addexternal(ruleaddr);
#endif /* !SOCKS_CLIENT */
   }
break;
case 103:
#line 1023 "config_parse.y"
	{
#if !SOCKS_CLIENT
      static ruleaddr_t mem;
      interfaceprotocol_t ifprotozero = { 0 };

      bzero(&mem, sizeof(mem));
      addrinit(&mem, 0);

      if (memcmp(&ifprotozero,
                 &sockscf.external.protocol,
                 sizeof(sockscf.external.protocol)) == 0) {
         slog(LOG_DEBUG, "%s: no address families explicitly enabled on "
                         "external interface.  Enabling default address "
                         "families",
                         function);

         sockscf.external.protocol.ipv4 = sockscf.external.protocol.ipv6 = 1;
      }
#endif /* !SOCKS_CLIENT */
   }
break;
case 104:
#line 1045 "config_parse.y"
	{
#if !SOCKS_CLIENT
      if (sockscf.external.addrc > 0) {
         log_interfaceprotocol_set_too_late(EXTERNALIF);
         sockdiopsexit(EXIT_FAILURE);
      }

      ifproto = &sockscf.external.protocol;
#endif /* !SOCKS_CLIENT */
   }
break;
case 106:
#line 1058 "config_parse.y"
	{
#if !SOCKS_CLIENT
      sockscf.external.rotation = ROTATION_NONE;
   }
break;
case 107:
#line 1062 "config_parse.y"
	{
      sockscf.external.rotation = ROTATION_SAMESAME;
   }
break;
case 108:
#line 1065 "config_parse.y"
	{
      sockscf.external.rotation = ROTATION_ROUTE;
#endif /* SOCKS_SERVER */
   }
break;
case 116:
#line 1080 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 118:
#line 1084 "config_parse.y"
	{
      if (yystack.l_mark[0].number < 0)
         yyerrorx("max route fails can not be negative (%ld)  Use \"0\" to "
                  "indicate routes should never be marked as bad",
                  (long)yystack.l_mark[0].number);

      sockscf.routeoptions.maxfail = yystack.l_mark[0].number;
   }
break;
case 119:
#line 1092 "config_parse.y"
	{
      if (yystack.l_mark[0].number < 0)
         yyerrorx("route failure expiry time can not be negative (%ld).  "
                  "Use \"0\" to indicate bad route marking should never expire",
                  (long)yystack.l_mark[0].number);

      sockscf.routeoptions.badexpire = yystack.l_mark[0].number;
   }
break;
case 120:
#line 1102 "config_parse.y"
	{ add_to_errlog = 1; }
break;
case 122:
#line 1105 "config_parse.y"
	{ add_to_errlog = 0; }
break;
case 124:
#line 1108 "config_parse.y"
	{
   int p;

   if ((add_to_errlog && failed_to_add_errlog)
   ||      (!add_to_errlog && failed_to_add_log)) {
      yywarnx("not adding logfile \"%s\"", yystack.l_mark[0].string);

      slog(LOG_ALERT,
           "%s: not trying to add logfile \"%s\" due to having already failed "
           "adding logfiles during this SIGHUP.  Only if all logfiles "
           "specified in the config can be added will we switch to using "
           "the new logfiles.  Until then, we will continue using only the "
           "old logfiles",
           function, yystack.l_mark[0].string);
   }
   else {
      p = socks_addlogfile(add_to_errlog ? &sockscf.errlog : &sockscf.log, yystack.l_mark[0].string);

#if !SOCKS_CLIENT
      if (sockscf.state.inited) {
         if (p == -1) {
            if (add_to_errlog) {
               sockscf.errlog       = old_errlog;
               failed_to_add_errlog = 1;
            }
            else {
               sockscf.log          = old_log;
               failed_to_add_log    = 1;
            }
         }
         else {
            sockdiops_freelogobject(add_to_errlog ?  &old_errlog : &old_log, 1);
            slog(LOG_DEBUG, "%s: added logfile \"%s\" to %s",
                 function, yystack.l_mark[0].string, add_to_errlog ? "errlog" : "logoutput");
         }
      }

      if (p == -1)
         slog(LOG_ALERT, "%s: could not (re)open logfile \"%s\": %s%s  %s",
              function,
              yystack.l_mark[0].string,
              strerror(errno),
              sockscf.state.inited ?
                  "." : "",
              sockscf.state.inited ?
                  "Will continue using old logfiles" : "");

#else /* SOCKS_CLIENT  */
      if (p == -1)
         /*
          * bad, but don't consider it fatal in the client.
          */
         yywarn("failed to add logfile %s", yystack.l_mark[0].string);
#endif /* SOCKS_CLIENT */
   }
}
break;
case 127:
#line 1169 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, sockscf.child.maxrequests, 0);
#endif /* !SOCKS_CLIENT */
   }
break;
case 131:
#line 1181 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.privileged_uid   = yystack.l_mark[0].uid.uid;
      sockscf.uid.privileged_gid   = yystack.l_mark[0].uid.gid;
      sockscf.uid.privileged_isset = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
break;
case 132:
#line 1194 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");
#else
      sockscf.uid.unprivileged_uid   = yystack.l_mark[0].uid.uid;
      sockscf.uid.unprivileged_gid   = yystack.l_mark[0].uid.gid;
      sockscf.uid.unprivileged_isset = 1;
#endif /* !HAVE_PRIVILEGES */
#endif /* !SOCKS_CLIENT */
   }
break;
case 133:
#line 1207 "config_parse.y"
	{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)

#if HAVE_PRIVILEGES
      yyerrorx("userid-settings not used on platforms with privileges");

#else
      sockscf.uid.libwrap_uid   = yystack.l_mark[0].uid.uid;
      sockscf.uid.libwrap_gid   = yystack.l_mark[0].uid.gid;
      sockscf.uid.libwrap_isset = 1;
#endif /* !HAVE_PRIVILEGES */

#else  /* !HAVE_LIBWRAP && (!SOCKS_CLIENT) */
      yyerrorx_nolib("libwrap");
#endif /* !HAVE_LIBWRAP (!SOCKS_CLIENT)*/
   }
break;
case 134:
#line 1226 "config_parse.y"
	{
      struct passwd *pw;

      if ((pw = getpwnam(yystack.l_mark[0].string)) == NULL)
         yyerror("getpwnam(3) says no such user \"%s\"", yystack.l_mark[0].string);

      yyval.uid.uid = pw->pw_uid;

      if ((pw = getpwuid(yyval.uid.uid)) == NULL)
         yyerror("getpwuid(3) says no such uid %lu (from user \"%s\")",
                 (unsigned long)yyval.uid.uid, yystack.l_mark[0].string);

      yyval.uid.gid = pw->pw_gid;
   }
break;
case 135:
#line 1242 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, timeout->tcpio, 1);
      timeout->udpio = timeout->tcpio;
   }
break;
case 136:
#line 1247 "config_parse.y"
	{
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, timeout->tcpio, 1);
   }
break;
case 137:
#line 1250 "config_parse.y"
	{
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, timeout->udpio, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 138:
#line 1256 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, timeout->negotiate, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 139:
#line 1263 "config_parse.y"
	{
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, timeout->connect, 1);
   }
break;
case 140:
#line 1268 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, timeout->tcp_fin_wait, 1);
#endif /* !SOCKS_CLIENT */
   }
break;
case 141:
#line 1276 "config_parse.y"
	{
#if SOCKS_CLIENT

       sockscf.option.debug = (int)yystack.l_mark[0].number;

#else /* !SOCKS_CLIENT */

      if (sockscf.initial.cmdline.debug_isset
      &&  sockscf.initial.cmdline.debug != yystack.l_mark[0].number)
         LOG_CMDLINE_OVERRIDE("debug",
                              sockscf.initial.cmdline.debug,
                              (int)yystack.l_mark[0].number,
                              "%d");
      else
         sockscf.option.debug = (int)yystack.l_mark[0].number;

#endif /* !SOCKS_CLIENT */
   }
break;
case 144:
#line 1300 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_allow_table  = strdup(yystack.l_mark[0].string)) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "%s: libwrap.allow: %s", function, hosts_allow_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 145:
#line 1314 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      if ((hosts_deny_table  = strdup(yystack.l_mark[0].string)) == NULL)
         yyerror(NOMEM);

      slog(LOG_DEBUG, "%s: libwrap.deny: %s", function, hosts_deny_table);
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 146:
#line 1328 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 1;
#else
      yyerrorx("libwrap.hosts_access requires libwrap library");
#endif /* HAVE_LIBWRAP */
   }
break;
case 147:
#line 1336 "config_parse.y"
	{
#if HAVE_LIBWRAP
      sockscf.option.hosts_access = 0;
#else
      yyerrorx_nolib("libwrap");
#endif /* HAVE_LIBWRAP */
#endif /* !SOCKS_CLIENT */
   }
break;
case 148:
#line 1346 "config_parse.y"
	{
#if !SOCKS_CLIENT
      sockscf.udpconnectdst = 1;
   }
break;
case 149:
#line 1350 "config_parse.y"
	{
      sockscf.udpconnectdst = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 150:
#line 1356 "config_parse.y"
	{
#if !SOCKS_CLIENT
      sockscf.dnsresolvdst = 1;
   }
break;
case 151:
#line 1360 "config_parse.y"
	{
      sockscf.dnsresolvdst = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 153:
#line 1369 "config_parse.y"
	{
#if !SOCKS_CLIENT
      sockscf.compat.sameport = 1;
   }
break;
case 154:
#line 1373 "config_parse.y"
	{
      sockscf.compat.draft_5_05 = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 158:
#line 1386 "config_parse.y"
	{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_FAKE;
   }
break;
case 159:
#line 1389 "config_parse.y"
	{
#if HAVE_NO_RESOLVESTUFF
         yyerrorx("resolveprotocol keyword not supported on this system");
#else
         sockscf.resolveprotocol = RESOLVEPROTOCOL_TCP;
#endif /* !HAVE_NO_RESOLVESTUFF */
   }
break;
case 160:
#line 1396 "config_parse.y"
	{
         sockscf.resolveprotocol = RESOLVEPROTOCOL_UDP;
   }
break;
case 163:
#line 1405 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETSCHEDULER
      yyerrorx("cpu scheduling policy is not supported on this system");
#else /* HAVE_SCHED_SETSCHEDULER */
      cpusetting_t *cpusetting;

      switch (yystack.l_mark[-4].number) {
         case PROC_MOTHER:
            cpusetting = &sockscf.cpu.mother;
            break;

         case PROC_MONITOR:
            cpusetting = &sockscf.cpu.monitor;
            break;

         case PROC_NEGOTIATE:
            cpusetting = &sockscf.cpu.negotiate;
            break;

         case PROC_REQUEST:
            cpusetting = &sockscf.cpu.request;
            break;

         case PROC_IO:
            cpusetting = &sockscf.cpu.io;
            break;

         default:
            SERRX(yystack.l_mark[-4].number);
      }

      bzero(&cpusetting->param, sizeof(cpusetting->param));

      cpusetting->scheduling_isset     = 1;
      cpusetting->policy               = yystack.l_mark[-2].number;
      cpusetting->param.sched_priority = (int)yystack.l_mark[0].number;
#endif /* HAVE_SCHED_SETSCHEDULER */
#endif /* !SOCKS_CLIENT */
   }
break;
case 164:
#line 1447 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if !HAVE_SCHED_SETAFFINITY
      yyerrorx("cpu scheduling affinity is not supported on this system");
#else /* HAVE_SCHED_SETAFFINITY */
      cpusetting_t *cpusetting;

      switch (yystack.l_mark[-2].number) {
         case PROC_MOTHER:
            cpusetting = &sockscf.cpu.mother;
            break;

         case PROC_MONITOR:
            cpusetting = &sockscf.cpu.monitor;
            break;

         case PROC_NEGOTIATE:
            cpusetting = &sockscf.cpu.negotiate;
            break;

         case PROC_REQUEST:
            cpusetting = &sockscf.cpu.request;
            break;

         case PROC_IO:
            cpusetting = &sockscf.cpu.io;
            break;

         default:
            SERRX(yystack.l_mark[-2].number);
      }

      cpu_zero(&cpusetting->mask);
      while (numberc-- > 0)
         if (numberv[numberc] == CPUMASK_ANYCPU) {
            const long cpus = sysconf(_SC_NPROCESSORS_ONLN);
            long i;

            if (cpus == -1)
               yyerror("sysconf(_SC_NPROCESSORS_ONLN) failed");

            for (i = 0; i < cpus; ++i)
               cpu_set((int)i, &cpusetting->mask);
         }
         else if (numberv[numberc] < 0)
            yyerrorx("invalid CPU number: %ld.  The CPU number can not be "
                     "negative", (long)numberv[numberc]);
         else
            cpu_set(numberv[numberc], &cpusetting->mask);

      free(numberv);
      numberv = NULL;
      numberc = 0;

      cpusetting->affinity_isset = 1;

#endif /* HAVE_SCHED_SETAFFINITY */
#endif /* !SOCKS_CLIENT */
   }
break;
case 165:
#line 1508 "config_parse.y"
	{
#if !SOCKS_CLIENT
      socketopt.level = yystack.l_mark[-1].number;
#endif /* !SOCKS_CLIENT */
   }
break;
case 167:
#line 1515 "config_parse.y"
	{
#if !SOCKS_CLIENT
   socketopt.optname = yystack.l_mark[0].number;
   socketopt.info    = optval2sockopt(socketopt.level, socketopt.optname);

   if (socketopt.info == NULL)
      slog(LOG_DEBUG,
           "%s: unknown/unsupported socket option: level %d, value %d",
           function, socketopt.level, socketopt.optname);
   else
      socketoptioncheck(&socketopt);
   }
break;
case 168:
#line 1527 "config_parse.y"
	{
      socketopt.info           = optid2sockopt((size_t)yystack.l_mark[0].number);
      SASSERTX(socketopt.info != NULL);

      socketopt.optname        = socketopt.info->value;

      socketoptioncheck(&socketopt);
#endif /* !SOCKS_CLIENT */
   }
break;
case 169:
#line 1538 "config_parse.y"
	{
      socketopt.optval.int_val = (int)yystack.l_mark[0].number;
      socketopt.opttype        = int_val;
   }
break;
case 170:
#line 1542 "config_parse.y"
	{
      const sockoptvalsym_t *p;

      if (socketopt.info == NULL)
         yyerrorx("the given socket option is unknown, so can not lookup "
                  "symbolic option value");

      if ((p = optval2valsym(socketopt.info->optid, yystack.l_mark[0].string)) == NULL)
         yyerrorx("symbolic value \"%s\" is unknown for socket option %s",
                  yystack.l_mark[0].string, sockopt2string(&socketopt, NULL, 0));

      socketopt.optval  = p->symval;
      socketopt.opttype = socketopt.info->opttype;
   }
break;
case 171:
#line 1559 "config_parse.y"
	{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 1;
   }
break;
case 172:
#line 1562 "config_parse.y"
	{ bzero(&socketopt, sizeof(socketopt));
                             socketopt.isinternalside = 0;
   }
break;
case 174:
#line 1571 "config_parse.y"
	{
#if !SOCKS_CLIENT
         sockscf.srchost.nodnsmismatch = 1;
   }
break;
case 175:
#line 1575 "config_parse.y"
	{
         sockscf.srchost.nodnsunknown = 1;
   }
break;
case 176:
#line 1578 "config_parse.y"
	{
         sockscf.srchost.checkreplyauth = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 179:
#line 1588 "config_parse.y"
	{
#if COVENANT
   STRCPY_CHECKLEN(sockscf.realmname,
                   yystack.l_mark[0].string,
                   sizeof(sockscf.realmname) - 1,
                   yyerrorx);
#else /* !COVENANT */
   yyerrorx("unknown keyword \"%s\"", yystack.l_mark[-2].string);
#endif /* !COVENANT */
}
break;
case 180:
#line 1600 "config_parse.y"
	{
#if !SOCKS_CLIENT

   cmethodv  = sockscf.cmethodv;
   cmethodc  = &sockscf.cmethodc;
  *cmethodc  = 0; /* reset. */

#endif /* !SOCKS_CLIENT */
   }
break;
case 182:
#line 1611 "config_parse.y"
	{
#if HAVE_SOCKS_RULES

      smethodv  = sockscf.smethodv;
      smethodc  = &sockscf.smethodc;
     *smethodc  = 0; /* reset. */

#else
      yyerrorx("\"socksmethod\" is not used in %s.  Only \"clientmethod\" "
               "is used",
               PRODUCT);
#endif /* !HAVE_SOCKS_RULES */
   }
break;
case 187:
#line 1633 "config_parse.y"
	{
      if (methodisvalid(yystack.l_mark[0].method, object_srule))
         ADDMETHOD(yystack.l_mark[0].method, *smethodc, smethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for socksmethods",
                  method2string(yystack.l_mark[0].method), yystack.l_mark[0].method);
   }
break;
case 191:
#line 1650 "config_parse.y"
	{
      if (methodisvalid(yystack.l_mark[0].method, object_crule))
         ADDMETHOD(yystack.l_mark[0].method, *cmethodc, cmethodv);
      else
         yyerrorx("method %s (%d) is not a valid method for clientmethods",
                  method2string(yystack.l_mark[0].method), yystack.l_mark[0].method);
   }
break;
case 192:
#line 1658 "config_parse.y"
	{ objecttype = object_monitor; }
break;
case 193:
#line 1658 "config_parse.y"
	{
#if !SOCKS_CLIENT
                        monitorinit(&monitor);
#endif /* !SOCKS_CLIENT */
}
break;
case 194:
#line 1663 "config_parse.y"
	{
#if !SOCKS_CLIENT
   pre_addmonitor(&monitor);

   addmonitor(&monitor);
#endif /* !SOCKS_CLIENT */
}
break;
case 195:
#line 1675 "config_parse.y"
	{ objecttype = object_crule; }
break;
case 196:
#line 1676 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if BAREFOOTD
      if (bounceto.atype == SOCKS_ADDR_NOTSET) {
         if (rule.verdict == VERDICT_PASS)
            yyerrorx("no address traffic should bounce to has been given");
         else {
            /*
             * allow no bounce-to address if it is a block, as the bounce-to
             * address will not be used in any case then.
             */
            bounceto.atype               = SOCKS_ADDR_IPV4;
            bounceto.addr.ipv4.ip.s_addr = htonl(INADDR_ANY);
            bounceto.port.tcp            = htons(0);
            bounceto.port.udp            = htons(0);
         }
      }

      rule.extra.bounceto = bounceto;
#endif /* BAREFOOTD */

      pre_addrule(&rule);
      addclientrule(&rule);
      post_addrule();
#endif /* !SOCKS_CLIENT */
   }
break;
case 200:
#line 1709 "config_parse.y"
	{
#if !SOCKS_CLIENT
         monitorif = NULL;
   }
break;
case 201:
#line 1713 "config_parse.y"
	{
         monitorif = &monitor.mstats->object.monitor.internal;
   }
break;
case 202:
#line 1716 "config_parse.y"
	{
         monitorif = &monitor.mstats->object.monitor.external;
#endif /* !SOCKS_CLIENT */
   }
break;
case 203:
#line 1722 "config_parse.y"
	{
#if !SOCKS_CLIENT
      alarmside = NULL;
   }
break;
case 204:
#line 1726 "config_parse.y"
	{
      *alarmside = RECVSIDE;
   }
break;
case 205:
#line 1729 "config_parse.y"
	{
      *alarmside = SENDSIDE;
#endif /* !SOCKS_CLIENT */
   }
break;
case 206:
#line 1735 "config_parse.y"
	{ alarminit(); }
break;
case 207:
#line 1736 "config_parse.y"
	{
#if !SOCKS_CLIENT
   alarm_data_limit_t limit;

   ASSIGN_NUMBER(yystack.l_mark[-2].number, >=, 0, limit.bytes, 0);
   ASSIGN_NUMBER(yystack.l_mark[0].number, >, 0, limit.seconds, 1);

   monitor.alarmsconfigured |= ALARM_DATA;

   if (monitor.alarm_data_aggregate != 0)
      yyerrorx("one aggregated data alarm has already been specified.  "
               "No more data alarms can be specified in this monitor");

   if (monitorif == NULL) {
      monitor.alarm_data_aggregate = ALARM_INTERNAL | ALARM_EXTERNAL;

      if (alarmside == NULL)
         monitor.alarm_data_aggregate |= ALARM_RECV | ALARM_SEND;

      if (alarmside == NULL || *alarmside == RECVSIDE) {
         monitor.mstats->object.monitor.internal.alarm.data.recv.isconfigured
         = 1;
         monitor.mstats->object.monitor.internal.alarm.data.recv.limit = limit;
      }

      if (alarmside == NULL || *alarmside == SENDSIDE) {
         monitor.mstats->object.monitor.internal.alarm.data.send.isconfigured
         = 1;
         monitor.mstats->object.monitor.internal.alarm.data.send.limit = limit;
      }

      if (alarmside == NULL || *alarmside == RECVSIDE) {
         monitor.mstats->object.monitor.external.alarm.data.recv.isconfigured
         = 1;
         monitor.mstats->object.monitor.external.alarm.data.recv.limit = limit;
      }

      if (alarmside == NULL || *alarmside == SENDSIDE) {
         monitor.mstats->object.monitor.external.alarm.data.send.isconfigured
         = 1;
         monitor.mstats->object.monitor.external.alarm.data.send.limit = limit;
      }
   }
   else {
      if (alarmside == NULL)
         monitor.alarm_data_aggregate = ALARM_RECV | ALARM_SEND;

      if (alarmside == NULL || *alarmside == RECVSIDE) {
         monitorif->alarm.data.recv.isconfigured = 1;
         monitorif->alarm.data.recv.limit        = limit;
      }

      if (alarmside == NULL || *alarmside == SENDSIDE) {
         monitorif->alarm.data.send.isconfigured = 1;
         monitorif->alarm.data.send.limit        = limit;
      }
   }
#endif /* !SOCKS_CLIENT */
   }
break;
case 209:
#line 1800 "config_parse.y"
	{
#if !SOCKS_CLIENT
   monitor.alarmsconfigured |= ALARM_TEST;

   if (monitorif == NULL) {
      monitor.mstats->object.monitor.internal.alarm.test.mtu.dotest = 1;
      monitor.mstats->object.monitor.external.alarm.test.mtu.dotest = 1;
   }
   else {
      monitorif->alarm.test.mtu.dotest = 1;
      monitorif->alarm.test.mtu.dotest = 1;
   }
#endif /* !SOCKS_CLIENT */
   }
break;
case 210:
#line 1818 "config_parse.y"
	{
#if !SOCKS_CLIENT
   alarm_disconnect_limit_t limit;

   ASSIGN_NUMBER(yystack.l_mark[-1].number, >, 0, limit.sessionc, 0);
   ASSIGN_NUMBER(yystack.l_mark[-3].number, >, 0, limit.disconnectc, 0);
   ASSIGN_NUMBER(yystack.l_mark[0].number, >, 0, limit.seconds, 1);

   if (monitor.alarm_disconnect_aggregate != 0)
      yyerrorx("one aggregated disconnect alarm has already been specified.  "
               "No more disconnect alarms can be specified in this monitor");

   monitor.alarmsconfigured |= ALARM_DISCONNECT;

   if (monitorif == NULL) {
      monitor.alarm_disconnect_aggregate = ALARM_INTERNAL | ALARM_EXTERNAL;

      monitor.mstats->object.monitor.internal.alarm.disconnect.isconfigured = 1;
      monitor.mstats->object.monitor.internal.alarm.disconnect.limit = limit;

        monitor.mstats->object.monitor.external.alarm.disconnect
      = monitor.mstats->object.monitor.internal.alarm.disconnect;
   }
   else {
      monitorif->alarm.disconnect.isconfigured = 1;
      monitorif->alarm.disconnect.limit        = limit;
   }
#endif /* !SOCKS_CLIENT */
   }
break;
case 211:
#line 1849 "config_parse.y"
	{
#if !SOCKS_CLIENT
               yyval.number = DEFAULT_ALARM_PERIOD;
#endif /* !SOCKS_CLIENT */
   }
break;
case 212:
#line 1854 "config_parse.y"
	{ yyval.number = yystack.l_mark[0].number; }
break;
case 215:
#line 1859 "config_parse.y"
	{ *hostidoption_isset = 1; }
break;
case 217:
#line 1863 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 219:
#line 1867 "config_parse.y"
	{
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 220:
#line 1872 "config_parse.y"
	{
#if !BAREFOOTD
                  yyerrorx("unsupported option");
#endif /* !BAREFOOTD */
   }
break;
case 222:
#line 1878 "config_parse.y"
	{
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 224:
#line 1886 "config_parse.y"
	{

#if SOCKS_CLIENT || !HAVE_SOCKS_HOSTID
      yyerrorx("hostid is not supported on this system");
#endif /* SOCKS_CLIENT || !HAVE_SOCKS_HOSTID */

      objecttype = object_hrule;
}
break;
case 225:
#line 1893 "config_parse.y"
	{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      if (hostid.atype != SOCKS_ADDR_NOTSET)
         yyerrorx("it does not make sense to set the hostid address in a "
                  "hostid-rule.  Use the \"from\" address to match the hostid "
                  "of the client");

      *hostidoption_isset = 1;

      pre_addrule(&rule);
      addhostidrule(&rule);
      post_addrule();
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
   }
break;
case 226:
#line 1911 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 230:
#line 1919 "config_parse.y"
	{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      addrinit(&hostid, 1);

#else /* HAVE_SOCKS_HOSTID */
      yyerrorx("hostid is not supported on this system");
#endif /* HAVE_SOCKS_HOSTID */

   }
break;
case 232:
#line 1930 "config_parse.y"
	{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
   ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, *hostindex, 0);
   ASSIGN_NUMBER(yystack.l_mark[0].number, <=, HAVE_MAX_HOSTIDS, *hostindex, 0);

#else
   yyerrorx("hostid is not supported on this system");
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
}
break;
case 233:
#line 1942 "config_parse.y"
	{ objecttype = object_srule; }
break;
case 234:
#line 1943 "config_parse.y"
	{
#if !SOCKS_CLIENT
#if !HAVE_SOCKS_RULES
   yyerrorx("socks-rules are not used in %s", PRODUCT);
#endif /* !HAVE_SOCKS_RULES */

      pre_addrule(&rule);
      addsocksrule(&rule);
      post_addrule();
#endif /* !SOCKS_CLIENT */
   }
break;
case 235:
#line 1957 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 243:
#line 1968 "config_parse.y"
	{
#if !SOCKS_CLIENT
                  session_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 245:
#line 1977 "config_parse.y"
	{
#if !SOCKS_CLIENT
                        checkmodule("bandwidth");
                        bw_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 253:
#line 1990 "config_parse.y"
	{ *hostidoption_isset = 1; }
break;
case 258:
#line 1995 "config_parse.y"
	{
#if !SOCKS_CLIENT
                     checkmodule("redirect");
#endif /* !SOCKS_CLIENT */
   }
break;
case 259:
#line 2000 "config_parse.y"
	{
#if !SOCKS_CLIENT
         if (rule.verdict == VERDICT_BLOCK && !socketopt.isinternalside)
            yyerrorx("it does not make sense to set a socket option for the "
                     "external side in a rule that blocks access; the external "
                     "side will never be accessed as the rule blocks access "
                     "to it");

         if (socketopt.isinternalside)
            if (socketopt.info != NULL && socketopt.info->calltype == preonly)
               yywarnx("to our knowledge the socket option \"%s\" can only be "
                       "correctly applied at pre-connection establishment "
                       "time, but by the time this rule is matched, the "
                       "connection will already have been established",
                       socketopt.info == NULL ? "unknown" :
                                                socketopt.info->name);

         if (!addedsocketoption(&rule.socketoptionc,
                                &rule.socketoptionv,
                                &socketopt))
            yywarn("could not add socketoption");
#endif /* !SOCKS_CLIENT */
   }
break;
case 290:
#line 2060 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->debug = (int)yystack.l_mark[0].number;
   }
break;
case 291:
#line 2065 "config_parse.y"
	{
      ldap->debug = (int)-yystack.l_mark[0].number;
 #else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 292:
#line 2074 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldap.domain,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.domain) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 293:
#line 2088 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP && HAVE_OPENLDAP
      ldap->mdepth = (int)yystack.l_mark[0].number;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("openldap");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 294:
#line 2099 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldap.certfile,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.certfile) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 295:
#line 2113 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(state->ldap.certpath,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.certpath) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 296:
#line 2127 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapurl, yystack.l_mark[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 297:
#line 2139 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapbasedn, yystack.l_mark[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 298:
#line 2151 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapbasedn, hextoutf8(yystack.l_mark[0].string, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 299:
#line 2163 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&state->ldap.ldapbasedn, hextoutf8(yystack.l_mark[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 300:
#line 2175 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->port = (int)yystack.l_mark[0].number;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 301:
#line 2186 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
   ldap->portssl = (int)yystack.l_mark[0].number;
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 302:
#line 2197 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->ssl = 1;
   }
break;
case 303:
#line 2202 "config_parse.y"
	{
      ldap->ssl = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 304:
#line 2211 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->auto_off = 1;
   }
break;
case 305:
#line 2216 "config_parse.y"
	{
      ldap->auto_off = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 306:
#line 2225 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->certcheck = 1;
   }
break;
case 307:
#line 2230 "config_parse.y"
	{
      ldap->certcheck = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 308:
#line 2239 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      ldap->keeprealm = 1;
   }
break;
case 309:
#line 2244 "config_parse.y"
	{
      ldap->keeprealm = 0;
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 310:
#line 2253 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKLEN(ldap->filter, yystack.l_mark[0].string, sizeof(state->ldap.filter) - 1, yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 311:
#line 2264 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldap->filter_AD,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.filter_AD) - 1,
                      yyerrorx);

#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 312:
#line 2279 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKUTFLEN(ldap->filter,
                          yystack.l_mark[0].string,
                          sizeof(state->ldap.filter) - 1,
                          yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 313:
#line 2293 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKUTFLEN(ldap->filter_AD,
                        yystack.l_mark[0].string,
                        sizeof(state->ldap.filter_AD) - 1,
                        yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 314:
#line 2307 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldap->attribute,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.attribute) - 1,
                      yyerrorx);

#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 315:
#line 2322 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      STRCPY_CHECKLEN(ldap->attribute_AD,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.attribute_AD) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 316:
#line 2336 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKUTFLEN(ldap->attribute,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.attribute) -1,
                      yyerrorx);
#else /* !HAVE_LDAP */
   yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 317:
#line 2350 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
   STRCPY_CHECKUTFLEN(ldap->attribute_AD,
                      yystack.l_mark[0].string,
                      sizeof(state->ldap.attribute_AD) - 1,
                      yyerrorx);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 318:
#line 2364 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapgroup, hextoutf8(yystack.l_mark[0].string, 0)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 319:
#line 2376 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, hextoutf8(yystack.l_mark[0].string, 1)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 320:
#line 2390 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      checkmodule("ldap");

      if (addlinkedname(&rule.ldapgroup, asciitoutf8(yystack.l_mark[0].string)) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 321:
#line 2404 "config_parse.y"
	{
#if SOCKS_SERVER
#if HAVE_LDAP
      if (addlinkedname(&rule.ldapserver, yystack.l_mark[0].string) == NULL)
         yyerror(NOMEM);
#else /* !HAVE_LDAP */
      yyerrorx_nolib("LDAP");
#endif /* !HAVE_LDAP */
#endif /* SOCKS_SERVER */
   }
break;
case 322:
#line 2416 "config_parse.y"
	{
#if HAVE_LDAP
#if SOCKS_SERVER
   STRCPY_CHECKLEN(state->ldap.keytab,
                   yystack.l_mark[0].string,
                   sizeof(state->ldap.keytab) - 1, yyerrorx);
#else
   yyerrorx("ldap keytab only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("LDAP");
#endif /* HAVE_LDAP */
   }
break;
case 324:
#line 2434 "config_parse.y"
	{
#if HAVE_GSSAPI
      gssapiencryption->nec = 1;
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 327:
#line 2448 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ruleinit(&rule);
      rule.verdict   = VERDICT_BLOCK;
   }
break;
case 328:
#line 2453 "config_parse.y"
	{
      ruleinit(&rule);
      rule.verdict   = VERDICT_PASS;
#endif /* !SOCKS_CLIENT */
   }
break;
case 332:
#line 2467 "config_parse.y"
	{
         state->command.bind = 1;
   }
break;
case 333:
#line 2470 "config_parse.y"
	{
         state->command.connect = 1;
   }
break;
case 334:
#line 2473 "config_parse.y"
	{
         state->command.udpassociate = 1;
   }
break;
case 335:
#line 2479 "config_parse.y"
	{
         state->command.bindreply = 1;
   }
break;
case 336:
#line 2483 "config_parse.y"
	{
         state->command.udpreply = 1;
   }
break;
case 340:
#line 2496 "config_parse.y"
	{
      state->protocol.tcp = 1;
   }
break;
case 341:
#line 2499 "config_parse.y"
	{
      state->protocol.udp = 1;
   }
break;
case 353:
#line 2528 "config_parse.y"
	{
#if !SOCKS_CLIENT
                        rule.ss_isinheritable = 1;
   }
break;
case 354:
#line 2532 "config_parse.y"
	{
                        rule.ss_isinheritable = 0;
#endif /* !SOCKS_CLIENT */
   }
break;
case 355:
#line 2538 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS(yystack.l_mark[0].number, ss.object.ss.max, 0);
      ss.object.ss.max       = yystack.l_mark[0].number;
      ss.object.ss.max_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 356:
#line 2547 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_THROTTLE_SECONDS(yystack.l_mark[-2].number, ss.object.ss.throttle.limit.clients, 0);
      ASSIGN_THROTTLE_CLIENTS(yystack.l_mark[0].number, ss.object.ss.throttle.limit.seconds, 0);
      ss.object.ss.throttle_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 361:
#line 2562 "config_parse.y"
	{
#if !SOCKS_CLIENT
      if ((ss.keystate.key = string2statekey(yystack.l_mark[0].string)) == key_unset)
         yyerrorx("%s is not a valid state key", yystack.l_mark[0].string);

      if (ss.keystate.key == key_hostid) {
#if HAVE_SOCKS_HOSTID

         *hostidoption_isset           = 1;
         ss.keystate.keyinfo.hostindex = DEFAULT_HOSTINDEX;

#else /* !HAVE_SOCKS_HOSTID */

         yyerrorx("hostid is not supported on this system");

#endif /* HAVE_SOCKS_HOSTID */
      }




#else /* SOCKS_CLIENT */

   SERRX(0);
#endif /* SOCKS_CLIENT */
   }
break;
case 362:
#line 2590 "config_parse.y"
	{
#if !SOCKS_CLIENT && HAVE_SOCKS_HOSTID
      hostindex = &ss.keystate.keyinfo.hostindex;
   }
break;
case 363:
#line 2594 "config_parse.y"
	{
      hostindex = &rule.hostindex; /* reset */
#endif /* !SOCKS_CLIENT && HAVE_SOCKS_HOSTID */
   }
break;
case 364:
#line 2601 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_MAXSESSIONS(yystack.l_mark[0].number, ss.object.ss.max_perstate, 0);
      ss.object.ss.max_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 365:
#line 2609 "config_parse.y"
	{
#if !SOCKS_CLIENT
   ASSIGN_THROTTLE_SECONDS(yystack.l_mark[-2].number, ss.object.ss.throttle_perstate.limit.clients, 0);
   ASSIGN_THROTTLE_CLIENTS(yystack.l_mark[0].number, ss.object.ss.throttle_perstate.limit.seconds, 0);
   ss.object.ss.throttle_perstate_isset = 1;
#endif /* !SOCKS_CLIENT */
}
break;
case 366:
#line 2618 "config_parse.y"
	{
#if !SOCKS_CLIENT
      ASSIGN_NUMBER(yystack.l_mark[0].number, >=, 0, bw.object.bw.maxbps, 0);
      bw.object.bw.maxbps_isset = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 368:
#line 2630 "config_parse.y"
	{
#if !SOCKS_CLIENT
         rule.log.connect = 1;
   }
break;
case 369:
#line 2634 "config_parse.y"
	{
         rule.log.data = 1;
   }
break;
case 370:
#line 2637 "config_parse.y"
	{
         rule.log.disconnect = 1;
   }
break;
case 371:
#line 2640 "config_parse.y"
	{
         rule.log.error = 1;
   }
break;
case 372:
#line 2643 "config_parse.y"
	{
         rule.log.iooperation = 1;
   }
break;
case 373:
#line 2646 "config_parse.y"
	{
         rule.log.tcpinfo = 1;
#endif /* !SOCKS_CLIENT */
   }
break;
case 376:
#line 2657 "config_parse.y"
	{
#if HAVE_PAM && (!SOCKS_CLIENT)
      STRCPY_CHECKLEN(state->pamservicename,
                      yystack.l_mark[0].string,
                      sizeof(state->pamservicename) -1,
                      yyerrorx);
#else
      yyerrorx_nolib("PAM");
#endif /* HAVE_PAM && (!SOCKS_CLIENT) */
   }
break;
case 377:
#line 2669 "config_parse.y"
	{
#if HAVE_BSDAUTH && SOCKS_SERVER
      STRCPY_CHECKLEN(state->bsdauthstylename,
                      yystack.l_mark[0].string,
                      sizeof(state->bsdauthstylename) - 1,
                      yyerrorx);
#else
      yyerrorx_nolib("bsdauth");
#endif /* HAVE_BSDAUTH && SOCKS_SERVER */
   }
break;
case 378:
#line 2682 "config_parse.y"
	{
#if HAVE_GSSAPI
      STRCPY_CHECKLEN(gssapiservicename,
                      yystack.l_mark[0].string,
                      sizeof(state->gssapiservicename) - 1,
                      yyerrorx);
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 379:
#line 2694 "config_parse.y"
	{
#if HAVE_GSSAPI
#if SOCKS_SERVER
      STRCPY_CHECKLEN(gssapikeytab,
                       yystack.l_mark[0].string,
                       sizeof(state->gssapikeytab) - 1,
                       yyerrorx);
#else
      yyerrorx("gssapi keytab setting is only applicable to Dante server");
#endif /* SOCKS_SERVER */
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 381:
#line 2713 "config_parse.y"
	{
#if HAVE_GSSAPI
      gssapiencryption->clear           = 1;
      gssapiencryption->integrity       = 1;
      gssapiencryption->confidentiality = 1;
   }
break;
case 382:
#line 2719 "config_parse.y"
	{
      gssapiencryption->clear = 1;
   }
break;
case 383:
#line 2722 "config_parse.y"
	{
      gssapiencryption->integrity = 1;
   }
break;
case 384:
#line 2725 "config_parse.y"
	{
      gssapiencryption->confidentiality = 1;
   }
break;
case 385:
#line 2728 "config_parse.y"
	{
      yyerrorx("gssapi per-message encryption not supported");
#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_GSSAPI */
   }
break;
case 389:
#line 2743 "config_parse.y"
	{
#if HAVE_LIBWRAP && (!SOCKS_CLIENT)
      struct request_info request;
      char tmp[LIBWRAPBUF];
      int errno_s, devnull;

      STRCPY_CHECKLEN(rule.libwrap,
                      yystack.l_mark[0].string,
                      sizeof(rule.libwrap) - 1,
                      yyerrorx);

      /* libwrap modifies the passed buffer, to test with a tmp one. */
      STRCPY_ASSERTSIZE(tmp, rule.libwrap);

      devnull = open("/dev/null", O_RDWR, 0);
      ++dry_run;
      errno_s = errno;

      errno = 0;

      request_init(&request, RQ_FILE, devnull, RQ_DAEMON, __progname, 0);
      if (setjmp(tcpd_buf) != 0)
         yyerror("bad libwrap line");
      process_options(tmp, &request);

      if (errno != 0)
         yywarn("possible libwrap/tcp-wrappers related configuration error");

      --dry_run;
      close(devnull);
      errno = errno_s;

#else
      yyerrorx_nolib("GSSAPI");
#endif /* HAVE_LIBWRAP && (!SOCKS_CLIENT) */

   }
break;
case 394:
#line 2795 "config_parse.y"
	{
#if BAREFOOTD
      yyerrorx("redirecting \"to\" an address does not make any sense in %s.  "
               "Instead specify the address you wanted to \"redirect\" "
               "data to as the \"bounce to\" address, as normal",
               PRODUCT);
#endif /* BAREFOOT */
   }
break;
case 406:
#line 2818 "config_parse.y"
	{
               if (!addedsocketoption(&route.socketoptionc,
                                      &route.socketoptionv,
                                      &socketopt))
                  yywarn("could not add socketoption");
   }
break;
case 407:
#line 2826 "config_parse.y"
	{ yyval.string = NULL; }
break;
case 410:
#line 2833 "config_parse.y"
	{
      addrinit(&src, 1);
   }
break;
case 411:
#line 2838 "config_parse.y"
	{
      addrinit(&dst, ipaddr_requires_netmask(to, objecttype));
   }
break;
case 412:
#line 2843 "config_parse.y"
	{
      addrinit(&rdr_from, 1);
   }
break;
case 413:
#line 2848 "config_parse.y"
	{
      addrinit(&rdr_to, 0);
   }
break;
case 414:
#line 2853 "config_parse.y"
	{
#if BAREFOOTD
      addrinit(&bounceto, 0);
#endif /* BAREFOOTD */
   }
break;
case 415:
#line 2861 "config_parse.y"
	{
      gwaddrinit(&gw);
   }
break;
case 424:
#line 2881 "config_parse.y"
	{ if (!netmask_required) yyerrorx_hasnetmask(); }
break;
case 425:
#line 2882 "config_parse.y"
	{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 426:
#line 2883 "config_parse.y"
	{ if (!netmask_required) yyerrorx_hasnetmask(); }
break;
case 427:
#line 2884 "config_parse.y"
	{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 428:
#line 2885 "config_parse.y"
	{ if (!netmask_required)
                                       yyerrorx_hasnetmask(); }
break;
case 429:
#line 2887 "config_parse.y"
	{ if (netmask_required)  yyerrorx_nonetmask();  }
break;
case 432:
#line 2891 "config_parse.y"
	{ /* for upnp; broadcasts on interface. */ }
break;
case 436:
#line 2900 "config_parse.y"
	{
      *atype = SOCKS_ADDR_IPV4;

      if (socks_inet_pton(AF_INET, yystack.l_mark[0].string, ipv4, NULL) != 1)
         yyerror("bad %s: %s", atype2string(*atype), yystack.l_mark[0].string);
   }
break;
case 437:
#line 2908 "config_parse.y"
	{
      if (yystack.l_mark[0].number < 0 || yystack.l_mark[0].number > 32)
         yyerrorx("bad %s netmask: %ld.  Legal range is 0 - 32",
                  atype2string(*atype), (long)yystack.l_mark[0].number);

      netmask_v4->s_addr = yystack.l_mark[0].number == 0 ? 0 : htonl(IPV4_FULLNETMASK << (32 - yystack.l_mark[0].number));
   }
break;
case 438:
#line 2915 "config_parse.y"
	{
      if (socks_inet_pton(AF_INET, yystack.l_mark[0].string, netmask_v4, NULL) != 1)
         yyerror("bad %s netmask: %s", atype2string(*atype), yystack.l_mark[0].string);
   }
break;
case 439:
#line 2921 "config_parse.y"
	{
      *atype = SOCKS_ADDR_IPV6;

      if (socks_inet_pton(AF_INET6, yystack.l_mark[0].string, ipv6, scopeid_v6) != 1)
         yyerror("bad %s: %s", atype2string(*atype), yystack.l_mark[0].string);
   }
break;
case 440:
#line 2929 "config_parse.y"
	{
      if (yystack.l_mark[0].number < 0 || yystack.l_mark[0].number > IPV6_NETMASKBITS)
         yyerrorx("bad %s netmask: %d.  Legal range is 0 - %d",
                  atype2string(*atype), (int)yystack.l_mark[0].number, IPV6_NETMASKBITS);

      *netmask_v6 = yystack.l_mark[0].number;
   }
break;
case 441:
#line 2938 "config_parse.y"
	{
      SASSERTX(strcmp(yystack.l_mark[0].string, "0") == 0);

      *atype = SOCKS_ADDR_IPVANY;
      ipvany->s_addr = htonl(0);
   }
break;
case 442:
#line 2946 "config_parse.y"
	{
      if (yystack.l_mark[0].number != 0)
         yyerrorx("bad %s netmask: %d.  Only legal value is 0",
                  atype2string(*atype), (int)yystack.l_mark[0].number);

      netmask_vany->s_addr = htonl(yystack.l_mark[0].number);
   }
break;
case 443:
#line 2956 "config_parse.y"
	{
      *atype = SOCKS_ADDR_DOMAIN;
      STRCPY_CHECKLEN(domain, yystack.l_mark[0].string, MAXHOSTNAMELEN - 1, yyerrorx);
   }
break;
case 444:
#line 2962 "config_parse.y"
	{
      *atype = SOCKS_ADDR_IFNAME;
      STRCPY_CHECKLEN(ifname, yystack.l_mark[0].string, MAXIFNAMELEN - 1, yyerrorx);
   }
break;
case 445:
#line 2969 "config_parse.y"
	{
      *atype = SOCKS_ADDR_URL;
      STRCPY_CHECKLEN(url, yystack.l_mark[0].string, MAXURLLEN - 1, yyerrorx);
   }
break;
case 446:
#line 2976 "config_parse.y"
	{ yyval.number = 0; }
break;
case 450:
#line 2982 "config_parse.y"
	{ yyval.number = 0; }
break;
case 454:
#line 2990 "config_parse.y"
	{
   if (ntohs(*port_tcp) > ntohs(ruleaddr->portend))
      yyerrorx("end port (%u) can not be less than start port (%u)",
      ntohs(*port_tcp), ntohs(ruleaddr->portend));
   }
break;
case 455:
#line 2998 "config_parse.y"
	{
      ASSIGN_PORTNUMBER(yystack.l_mark[0].number, *port_tcp);
      ASSIGN_PORTNUMBER(yystack.l_mark[0].number, *port_udp);
   }
break;
case 456:
#line 3004 "config_parse.y"
	{
      ASSIGN_PORTNUMBER(yystack.l_mark[0].number, ruleaddr->portend);
      ruleaddr->operator   = range;
   }
break;
case 457:
#line 3010 "config_parse.y"
	{
      struct servent   *service;

      if ((service = getservbyname(yystack.l_mark[0].string, "tcp")) == NULL) {
         if (state->protocol.tcp)
            yyerrorx("unknown tcp protocol: %s", yystack.l_mark[0].string);

         *port_tcp = htons(0);
      }
      else
         *port_tcp = (in_port_t)service->s_port;

      if ((service = getservbyname(yystack.l_mark[0].string, "udp")) == NULL) {
         if (state->protocol.udp)
               yyerrorx("unknown udp protocol: %s", yystack.l_mark[0].string);

            *port_udp = htons(0);
      }
      else
         *port_udp = (in_port_t)service->s_port;

      if (*port_tcp == htons(0) && *port_udp == htons(0))
         yyerrorx("unknown tcp/udp protocol");

      /* if one protocol is unset, set to same as the other. */
      if (*port_tcp == htons(0))
         *port_tcp = *port_udp;
      else if (*port_udp == htons(0))
         *port_udp = *port_tcp;

      yyval.number = (size_t)*port_udp;
   }
break;
case 458:
#line 3045 "config_parse.y"
	{
      *operator = string2operator(yystack.l_mark[0].string);
   }
break;
case 460:
#line 3054 "config_parse.y"
	{
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER(yystack.l_mark[0].number, rule.udprange.start);
#endif /* SOCKS_SERVER */
   }
break;
case 461:
#line 3061 "config_parse.y"
	{
#if SOCKS_SERVER
   ASSIGN_PORTNUMBER(yystack.l_mark[0].number, rule.udprange.end);
   rule.udprange.op  = range;

   if (ntohs(rule.udprange.start) > ntohs(rule.udprange.end))
      yyerrorx("end port (%d) can not be less than start port (%u)",
               (int)yystack.l_mark[0].number, ntohs(rule.udprange.start));
#endif /* SOCKS_SERVER */
   }
break;
case 462:
#line 3073 "config_parse.y"
	{
      addnumber(&numberc, &numberv, yystack.l_mark[0].number);
   }
break;
#line 6204 "config_parse.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
        if (yychar < 0)
        {
            if ((yychar = YYLEX) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
