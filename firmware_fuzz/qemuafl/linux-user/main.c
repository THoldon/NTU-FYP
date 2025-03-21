/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/units.h"
#include "qemu/accel.h"
#include "sysemu/tcg.h"
#include "qemu-version.h"
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/shm.h>

#include "qapi/error.h"
#include "qemu.h"
#include "qemu/path.h"
#include "qemu/queue.h"
#include "qemu/config-file.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu/plugin.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg/tcg.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "qemu/guest-random.h"
#include "elf.h"
#include "trace/control.h"
#include "target_elf.h"
#include "cpu_loop-common.h"
#include "crypto/init.h"

#include "qemuafl/qasan-qemu.h"

char *exec_path;

int singlestep;
static const char *argv0;
static const char *gdbstub;
static envlist_t *envlist;
static const char *cpu_model;
static const char *cpu_type;
static const char *seed_optarg;
unsigned long mmap_min_addr;
uintptr_t guest_base;
bool have_guest_base;
target_ulong main_bin_start;
target_ulong main_bin_end;
int bk_stdin_fd = -1;
int bk_stdout_fd = -1;
FILE *bk_stdin;
FILE *bk_stdout;

// pconly
bool program_code_only = 0;
char filter_buf[512];  // GREENHOUSE PATCH

/*
    * Used to implement backwards-compatibility for the `-strace`, and
    * QEMU_STRACE options. Without this, the QEMU_LOG can be overwritten by
    * -strace, or vice versa.
    */
static bool enable_strace;

/*
 * The last log mask given by the user in an environment variable or argument.
 * Used to support command line arguments overriding environment variables.
 */
static int last_log_mask;

/*
 * When running 32-on-64 we should make sure we can fit all of the possible
 * guest address space into a contiguous chunk of virtual host memory.
 *
 * This way we will never overlap with our own libraries or binaries or stack
 * or anything else that QEMU maps.
 *
 * Many cpus reserve the high bit (or more than one for some 64-bit cpus)
 * of the address for the kernel.  Some cpus rely on this and user space
 * uses the high bit(s) for pointer tagging and the like.  For them, we
 * must preserve the expected address space.
 */
#ifndef MAX_RESERVED_VA
# if HOST_LONG_BITS > TARGET_VIRT_ADDR_SPACE_BITS
#  if TARGET_VIRT_ADDR_SPACE_BITS == 32 && \
      (TARGET_LONG_BITS == 32 || defined(TARGET_ABI32))
/* There are a number of places where we assign reserved_va to a variable
   of type abi_ulong and expect it to fit.  Avoid the last page.  */
#   define MAX_RESERVED_VA(CPU)  (0xfffffffful & TARGET_PAGE_MASK)
#  else
#   define MAX_RESERVED_VA(CPU)  (1ul << TARGET_VIRT_ADDR_SPACE_BITS)
#  endif
# else
#  define MAX_RESERVED_VA(CPU)  0
# endif
#endif

unsigned long reserved_va;

static void usage(int exitcode);

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;

#if defined(TARGET_I386)
int cpu_get_pic_interrupt(CPUX86State *env)
{
    return -1;
}
#endif

/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    start_exclusive();
    mmap_fork_start();
    cpu_list_lock();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        CPUState *cpu, *next_cpu;
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != thread_cpu) {
                QTAILQ_REMOVE_RCU(&cpus, cpu, node);
            }
        }
        qemu_init_cpu_list();
        gdbserver_fork(thread_cpu);
        /* qemu_init_cpu_list() takes care of reinitializing the
         * exclusive state, so we don't need to end_exclusive() here.
         */
    } else {
        cpu_list_unlock();
        end_exclusive();
    }
}

__thread CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void qemu_cpu_kick(CPUState *cpu)
{
    cpu_exit(cpu);
}

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    ts->used = 1;
    ts->sigaltstack_used = (struct target_sigaltstack) {
        .ss_sp = 0,
        .ss_size = 0,
        .ss_flags = TARGET_SS_DISABLE,
    };
}

CPUArchState *cpu_copy(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    CPUState *new_cpu = cpu_create(cpu_type);
    CPUArchState *new_env = new_cpu->env_ptr;
    CPUBreakpoint *bp;
    CPUWatchpoint *wp;

    /* Reset non arch specific state */
    cpu_reset(new_cpu);

    memcpy(new_env, env, sizeof(CPUArchState));

    /* Clone all break/watchpoints.
       Note: Once we support ptrace with hw-debug register access, make sure
       BP_CPU break/watchpoints are handled correctly on clone. */
    QTAILQ_INIT(&new_cpu->breakpoints);
    QTAILQ_INIT(&new_cpu->watchpoints);
    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        cpu_breakpoint_insert(new_cpu, bp->pc, bp->flags, NULL);
    }
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        cpu_watchpoint_insert(new_cpu, wp->vaddr, wp->len, wp->flags, NULL);
    }

    return new_env;
}

/* A shorthand way to suppress the warnings that you are ignoring the return value of asprintf() */
static inline void ignore_result(long long int unused_result)
{
    (void) unused_result;
}

/* Get libqasan path. */
#ifndef AFL_PATH
  #define AFL_PATH "/usr/local/lib/afl/"
#endif
static char *get_libqasan_path(char *own_loc)
{
    if (!unlikely(own_loc)) {
        fprintf(stderr, "BUG: param own_loc is NULL\n");
        exit(EXIT_FAILURE);
    }

    char *tmp, *cp = NULL, *rsl, *own_copy;

    tmp = getenv("AFL_PATH");
    if (tmp) {
        ignore_result(asprintf(&cp, "%s/libqasan.so", tmp));
        if (access(cp, X_OK)) {
            fprintf(stderr, "Unable to find '%s'\n", tmp);
            exit(EXIT_FAILURE);
        }

        return cp;
    }

    own_copy = strdup(own_loc);
    rsl = strrchr(own_copy, '/');
    if (rsl) {
        *rsl = 0;

        ignore_result(asprintf(&cp, "%s/libqasan.so", own_copy));
        free(own_copy);

        if (!access(cp, X_OK)) { return cp; }

    } else {
        free(own_copy);
    }

    if (!access(AFL_PATH "/libqasan.so", X_OK)) {
        if (cp) { free(cp); }

        return strdup(AFL_PATH "/libqasan.so");
    }

    /* This is an AFL error message, but since it is in QEMU it can't
       have all the pretty formatting of AFL without importing
       a bunch of AFL pieces. */
    fprintf(stderr, "\n" "" "[-] " ""
        "Oops, unable to find the 'libqasan.so' binary. The binary must be "
        "built\n"
        "    separately by following the instructions in "
        "qemu_mode/libqasan/README.md. "
        "If you\n"
        "    already have the binary installed, you may need to specify "
        "AFL_PATH in the\n"
        "    environment.\n");

    fprintf(stderr, "Failed to locate 'libqasan.so'.\n");
    exit(EXIT_FAILURE);
}

static void handle_arg_help(const char *arg)
{
    usage(EXIT_SUCCESS);
}

static void handle_arg_log(const char *arg)
{
    last_log_mask = qemu_str_to_log_mask(arg);
    if (!last_log_mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_dfilter(const char *arg)
{
    qemu_set_dfilter_ranges(arg, &error_fatal);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg, &error_fatal);
}

static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_unset_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_unsetenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}

static void handle_arg_argv0(const char *arg)
{
    argv0 = strdup(arg);
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    guest_stack_size = strtoul(arg, &p, 0);
    if (guest_stack_size == 0) {
        usage(EXIT_FAILURE);
    }

    if (*p == 'M') {
        guest_stack_size *= MiB;
    } else if (*p == 'k' || *p == 'K') {
        guest_stack_size *= KiB;
    }
}

static void handle_arg_execve(const char *arg)
{
    qemu_set_execve_path(arg);
}

static void handle_arg_hackproc(const char *arg)
{
    qemu_set_hackproc(arg);
}

static void handle_arg_hackbind(const char *arg)
{
    qemu_set_hackbind(arg);
}

static void handle_arg_hacksysinfo(const char *arg)
{
    qemu_set_hacksysinfo(arg);
}

static void handle_arg_norandom(const char *arg)
{
    qemu_set_norandom(arg);
}

static void handle_arg_pconly(const char *arg) {
  // fprintf(stderr, "[GreenHouseQEMU] handle_arg_pconly\n");
  program_code_only = 1;
}

static void handle_arg_hookhack(const char *arg)
{
    qemu_set_hookhack(arg);
}

static void handle_arg_ld_prefix(const char *arg)
{
    interp_prefix = strdup(arg);
}

static void handle_arg_pagesize(const char *arg)
{
    qemu_host_page_size = atoi(arg);
    if (qemu_host_page_size == 0 ||
        (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
        fprintf(stderr, "page size must be a power of two\n");
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_seed(const char *arg)
{
    seed_optarg = arg;
}

static void handle_arg_gdb(const char *arg)
{
    gdbstub = g_strdup(arg);
}

static void handle_arg_uname(const char *arg)
{
    qemu_uname_release = strdup(arg);
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = strdup(arg);
    if (cpu_model == NULL || is_help_option(cpu_model)) {
        /* XXX: implement xxx_cpu_list for targets that still miss it */
#if defined(cpu_list)
        cpu_list();
#endif
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_guest_base(const char *arg)
{
    guest_base = strtol(arg, NULL, 0);
    have_guest_base = true;
}

static void handle_arg_reserved_va(const char *arg)
{
    char *p;
    int shift = 0;
    reserved_va = strtoul(arg, &p, 0);
    switch (*p) {
    case 'k':
    case 'K':
        shift = 10;
        break;
    case 'M':
        shift = 20;
        break;
    case 'G':
        shift = 30;
        break;
    }
    if (shift) {
        unsigned long unshifted = reserved_va;
        p++;
        reserved_va <<= shift;
        if (reserved_va >> shift != unshifted) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    }
    if (*p) {
        fprintf(stderr, "Unrecognised -R size suffix '%s'\n", p);
        exit(EXIT_FAILURE);
    }
}

static void handle_arg_singlestep(const char *arg)
{
    singlestep = 1;
}

static void handle_arg_strace(const char *arg)
{
    enable_strace = true;
}

static void handle_arg_version(const char *arg)
{
    printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION
           "\n" QEMU_COPYRIGHT "\n");
    exit(EXIT_SUCCESS);
}

static void handle_arg_trace(const char *arg)
{
    trace_opt_parse(arg);
}

#if defined(TARGET_XTENSA)
static void handle_arg_abi_call0(const char *arg)
{
    xtensa_set_abi_call0();
}
#endif

static QemuPluginList plugins = QTAILQ_HEAD_INITIALIZER(plugins);

#ifdef CONFIG_PLUGIN
static void handle_arg_plugin(const char *arg)
{
    qemu_plugin_opt_parse(arg, &plugins);
}
#endif

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h", "", false, handle_arg_help, "", "print this help"},
    {"help", "", false, handle_arg_help, "", ""},
    {"g", "QEMU_GDB", true, handle_arg_gdb, "port",
     "wait gdb connection to 'port'"},
    {"L", "QEMU_LD_PREFIX", true, handle_arg_ld_prefix, "path",
     "set the elf interpreter prefix to 'path'"},
    {"hackbind", "QEMU_HACKBIND", false, handle_arg_hackbind, "",
     "use hack to get around ipv6 addrs and conflicting binds"},
    {"hackproc", "QEMU_HACKPROC", false, handle_arg_hackproc, "",
     "use hack to get around needing to mount a writable /proc"},
    {"hacksysinfo", "QEMU_SYSINFO", false, handle_arg_hacksysinfo, "",
     "use hack to get around needing to mount a writable /proc"},
    {"norandom", "QEMU_NORANDOM", false, handle_arg_norandom, "",
     "hook time-like syscall to de-random the generation of random number"},
    {"execve", "QEMU_EXECVE", true, handle_arg_execve, "path",
     "use interpreter at 'path' when a process calls execve()"},
    {"pconly", "QEMU_PCONLY", false, handle_arg_pconly,  // GREENHOUSE PATCH
     "", "filter non-program code ranges when logging"},
    {"hookhack", "QEMU_HOOKHACK", false, handle_arg_hookhack, "",
     "use hack to force the target binary to read from stdin"},
    {"s", "QEMU_STACK_SIZE", true, handle_arg_stack_size, "size",
     "set the stack size to 'size' bytes"},
    {"cpu", "QEMU_CPU", true, handle_arg_cpu, "model",
     "select CPU (-cpu help for list)"},
    {"E", "QEMU_SET_ENV", true, handle_arg_set_env, "var=value",
     "sets targets environment variable (see below)"},
    {"U", "QEMU_UNSET_ENV", true, handle_arg_unset_env, "var",
     "unsets targets environment variable (see below)"},
    {"0", "QEMU_ARGV0", true, handle_arg_argv0, "argv0",
     "forces target process argv[0] to be 'argv0'"},
    {"r", "QEMU_UNAME", true, handle_arg_uname, "uname",
     "set qemu uname release string to 'uname'"},
    {"B", "QEMU_GUEST_BASE", true, handle_arg_guest_base, "address",
     "set guest_base address to 'address'"},
    {"R", "QEMU_RESERVED_VA", true, handle_arg_reserved_va, "size",
     "reserve 'size' bytes for guest virtual address space"},
    {"d", "QEMU_LOG", true, handle_arg_log, "item[,...]",
     "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"dfilter", "QEMU_DFILTER", true, handle_arg_dfilter, "range[,...]",
     "filter logging based on address range"},
    {"D", "QEMU_LOG_FILENAME", true, handle_arg_log_filename, "logfile",
     "write logs to 'logfile' (default stderr)"},
    {"p", "QEMU_PAGESIZE", true, handle_arg_pagesize, "pagesize",
     "set the host page size to 'pagesize'"},
    {"singlestep", "QEMU_SINGLESTEP", false, handle_arg_singlestep, "",
     "run in singlestep mode"},
    {"strace", "QEMU_STRACE", false, handle_arg_strace, "", "log system calls"},
    {"seed", "QEMU_RAND_SEED", true, handle_arg_seed, "",
     "Seed for pseudo-random number generator"},
    {"trace", "QEMU_TRACE", true, handle_arg_trace, "",
     "[[enable=]<pattern>][,events=<file>][,file=<file>]"},
#ifdef CONFIG_PLUGIN
    {"plugin", "QEMU_PLUGIN", true, handle_arg_plugin, "",
     "[file=]<file>[,arg=<string>]"},
#endif
    {"version", "QEMU_VERSION", false, handle_arg_version, "",
     "display version information and exit"},
#if defined(TARGET_XTENSA)
    {"xtensa-abi-call0", "QEMU_XTENSA_ABI_CALL0", false, handle_arg_abi_call0,
     "", "assume CALL0 Xtensa ABI"},
#endif
    {NULL, NULL, false, NULL, NULL, NULL}};

static void usage(int exitcode)
{
    const struct qemu_argument *arginfo;
    int maxarglen;
    int maxenvlen;

    printf("usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for " TARGET_NAME " emulation)\n"
           "\n"
           "Options and associated environment variables:\n"
           "\n");

    /* Calculate column widths. We must always have at least enough space
     * for the column header.
     */
    maxarglen = strlen("Argument");
    maxenvlen = strlen("Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        int arglen = strlen(arginfo->argv);
        if (arginfo->has_arg) {
            arglen += strlen(arginfo->example) + 1;
        }
        if (strlen(arginfo->env) > maxenvlen) {
            maxenvlen = strlen(arginfo->env);
        }
        if (arglen > maxarglen) {
            maxarglen = arglen;
        }
    }

    printf("%-*s %-*s Description\n", maxarglen+1, "Argument",
            maxenvlen, "Env-variable");

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->has_arg) {
            printf("-%s %-*s %-*s %s\n", arginfo->argv,
                   (int)(maxarglen - strlen(arginfo->argv) - 1),
                   arginfo->example, maxenvlen, arginfo->env, arginfo->help);
        } else {
            printf("-%-*s %-*s %s\n", maxarglen, arginfo->argv,
                    maxenvlen, arginfo->env,
                    arginfo->help);
        }
    }

    printf("\n"
           "Defaults:\n"
           "QEMU_LD_PREFIX  = %s\n"
           "QEMU_STACK_SIZE = %ld byte\n",
           interp_prefix,
           guest_stack_size);

    printf("\n"
           "You can use -E and -U options or the QEMU_SET_ENV and\n"
           "QEMU_UNSET_ENV environment variables to set and unset\n"
           "environment variables for the target process.\n"
           "It is possible to provide several variables by separating them\n"
           "by commas in getsubopt(3) style. Additionally it is possible to\n"
           "provide the -E and -U options multiple times.\n"
           "The following lines are equivalent:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "    -E var1=val2,var2=val2 -U LD_PRELOAD,LD_DEBUG\n"
           "    QEMU_SET_ENV=var1=val2,var2=val2 QEMU_UNSET_ENV=LD_PRELOAD,LD_DEBUG\n"
           "Note that if you provide several changes to a single variable\n"
           "the last change will stay in effect.\n"
           "\n"
           QEMU_HELP_BOTTOM "\n");

    exit(exitcode);
}

static int parse_args(int argc, char **argv)
{
    const char *r;
    int optind;
    const struct qemu_argument *arginfo;

    for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
        if (arginfo->env == NULL) {
            continue;
        }

        r = getenv(arginfo->env);
        if (r != NULL) {
            arginfo->handle_opt(r);
        }
    }

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        }
        /* Treat --foo the same as -foo.  */
        if (r[0] == '-') {
            r++;
        }

        for (arginfo = arg_table; arginfo->handle_opt != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        (void) fprintf(stderr,
                            "qemu: missing argument for option '%s'\n", r);
                        exit(EXIT_FAILURE);
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        /* no option matched the current argv */
        if (arginfo->handle_opt == NULL) {
            (void) fprintf(stderr, "qemu: unknown option '%s'\n", r);
            exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        (void) fprintf(stderr, "qemu: no user program specified\n");
        exit(EXIT_FAILURE);
    }

    exec_path = argv[optind];

    return optind;
}

int main(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    int i;
    int ret;
    int execfd;
    int log_mask;
    unsigned long max_reserved_va;

    use_qasan = !!getenv("AFL_USE_QASAN");

    if (getenv("QASAN_MAX_CALL_STACK"))
      qasan_max_call_stack = atoi(getenv("QASAN_MAX_CALL_STACK"));
    if (getenv("QASAN_SYMBOLIZE"))
      qasan_symbolize = atoi(getenv("QASAN_SYMBOLIZE"));

#if defined(ASAN_GIOVESE) && !defined(DO_NOT_USE_QASAN)
    if (use_qasan)
      asan_giovese_init();
#endif

    error_init(argv[0]);
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Add AFL_PRELOAD for qasan if it is enabled */
    if(use_qasan) {
        char *preload = getenv("AFL_PRELOAD");
        char *libqasan = get_libqasan_path(argv[0]);

        if (!preload) {
            setenv("AFL_PRELOAD", libqasan, 0);
        } else {
            /* NOTE: If there is more than one in the list, LD_PRELOAD allows spaces or colons
                     as separators (but no escaping provided), but DYLD_INSERT_LIBRARIES allows only colons.
                     Prefer colons for maximum compatibility, but use space if the string already has any. */
            char * afl_preload;
            if (strchr(preload, ' ')) {
                ignore_result(asprintf(&afl_preload, "%s %s", libqasan, preload));
            } else {
                ignore_result(asprintf(&afl_preload, "%s:%s", libqasan, preload));
            }

            setenv("AFL_PRELOAD", afl_preload, 1);
            free(afl_preload);
        }
        free(libqasan);
    }

    /* Expand AFL_PRELOAD to append preload libraries */
    char *afl_preload = getenv("AFL_PRELOAD");
    if (afl_preload) {
        /* NOTE: If there is more than one in the list, LD_PRELOAD allows spaces or colons
                 as separators, but DYLD_INSERT_LIBRARIES allows only colons.
                 Maybe we should attempt to normalize the list here before we assign it? */
        char * ld_preload;
        ignore_result(asprintf(&ld_preload, "LD_PRELOAD=%s", afl_preload));
        envlist_setenv(envlist, ld_preload);

        char * dyld_insert;
        ignore_result(asprintf(&dyld_insert, "DYLD_INSERT_LIBRARIES=%s", afl_preload));
        envlist_setenv(envlist, dyld_insert);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;

    qemu_add_opts(&qemu_trace_opts);
    qemu_plugin_add_opts();

    optind = parse_args(argc, argv);

    log_mask = last_log_mask | (enable_strace ? LOG_STRACE : 0);
    if (log_mask) {
        qemu_log_needs_buffers();
        qemu_set_log(log_mask);
    }

    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file();
    qemu_plugin_load_list(&plugins, &error_fatal);

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    init_qemu_uname_release();

    execfd = qemu_getauxval(AT_EXECFD);
    if (execfd == 0) {
        execfd = open(exec_path, O_RDONLY);
        if (execfd < 0) {
            printf("Error while loading %s: %s\n", exec_path, strerror(errno));
            _exit(EXIT_FAILURE);
        }
    }

    if (cpu_model == NULL) {
        cpu_model = cpu_get_model(get_elf_eflags(execfd));
    }
    cpu_type = parse_cpu_option(cpu_model);

    /* init tcg before creating CPUs and to get qemu_host_page_size */
    {
        AccelClass *ac = ACCEL_GET_CLASS(current_accel());

        ac->init_machine(NULL);
        accel_init_interfaces(ac);
    }
    cpu = cpu_create(cpu_type);
    env = cpu->env_ptr;
    cpu_reset(cpu);
    thread_cpu = cpu;

    /*
     * Reserving too much vm space via mmap can run into problems
     * with rlimits, oom due to page table creation, etc.  We will
     * still try it, if directed by the command-line option, but
     * not by default.
     */
    max_reserved_va = MAX_RESERVED_VA(cpu);
    if (reserved_va != 0) {
        if (max_reserved_va && reserved_va > max_reserved_va) {
            fprintf(stderr, "Reserved virtual address too big\n");
            exit(EXIT_FAILURE);
        }
    } else if (HOST_LONG_BITS == 64 && TARGET_VIRT_ADDR_SPACE_BITS <= 32) {
        /*
         * reserved_va must be aligned with the host page size
         * as it is used with mmap()
         */
        reserved_va = max_reserved_va & qemu_host_page_mask;
    }

    {
        Error *err = NULL;
        if (seed_optarg != NULL) {
            qemu_guest_random_seed_main(seed_optarg, &err);
        } else {
            qcrypto_init(&err);
        }
        if (err) {
            error_reportf_err(err, "cannot initialize crypto: ");
            exit(1);
        }
    }

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);

    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1 && tmp != 0) {
                mmap_min_addr = tmp;
                qemu_log_mask(CPU_LOG_PAGE, "host mmap_min_addr=0x%lx\n",
                              mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * We prefer to not make NULL pointers accessible to QEMU.
     * If we're in a chroot with no /proc, fall back to 1 page.
     */
    if (mmap_min_addr == 0) {
        mmap_min_addr = qemu_host_page_size;
        qemu_log_mask(CPU_LOG_PAGE,
                      "host mmap_min_addr=0x%lx (fallback)\n",
                      mmap_min_addr);
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
        (void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
        exit(EXIT_FAILURE);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    cpu->opaque = ts;
    task_settid(ts);

    ret = loader_exec(execfd, exec_path, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error while loading %s: %s\n", exec_path, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    for (wrk = target_environ; *wrk; wrk++) {
        g_free(*wrk);
    }

    g_free(target_environ);

    main_bin_start = info->start_code;
    main_bin_end = info->end_code;

    bk_stdin_fd = dup2(0, 1337);
    bk_stdout_fd = dup2(1, 1338);
    if(bk_stdin_fd < 0 || bk_stdout_fd < 0) {
        puts("Error when backing up stdin and stdout"); // ulimit -n 2048
        _exit(EXIT_FAILURE);
    }

    bk_stdin = fdopen(bk_stdin_fd, "r");
    bk_stdout = fdopen(bk_stdout_fd, "w");
    setbuf(bk_stdin, NULL);
    setbuf(bk_stdout, NULL);
    if(bk_stdin == NULL || bk_stdout == NULL) {
        puts("Error creating backup stdin and stdout file structs");
        _exit(EXIT_FAILURE);
    }
    fprintf(stderr, "[HOOK] %d %d\n", bk_stdin_fd, bk_stdout_fd);
    fprintf(bk_stdout, "[HOOK2] %d %d\n", bk_stdin_fd, bk_stdout_fd);

    if (qemu_loglevel_mask(CPU_LOG_PAGE)) {
        qemu_log("guest_base  %p\n", (void *)guest_base);
        log_page_dump("binary load");

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n", info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n", info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n", info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
        qemu_log("argv_start  0x" TARGET_ABI_FMT_lx "\n", info->arg_start);
        qemu_log("env_start   0x" TARGET_ABI_FMT_lx "\n",
                 info->arg_end + (abi_ulong)sizeof(abi_ulong));
        qemu_log("auxv_start  0x" TARGET_ABI_FMT_lx "\n", info->saved_auxv);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

    // GREENHOUSE PATCH
    if (program_code_only == 1) {
        memset(filter_buf, 0, 512);
        snprintf(filter_buf, 512, "0x%lx..0x%lx", (unsigned long)info->start_code, (unsigned long)info->end_code);
        // fprintf(stderr, "[qemu] Setting filterbuf: %s\n", filter_buf);
        qemu_set_dfilter_ranges(filter_buf, &error_fatal);
    }

    /* Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
       generating the prologue until now so that the prologue can take
       the real value of GUEST_BASE into account.  */
    tcg_prologue_init(tcg_ctx);
    tcg_region_init();

    target_cpu_copy_regs(env, regs);

    if (gdbstub) {
        if (gdbserver_start(gdbstub) < 0) {
            fprintf(stderr, "qemu: could not open gdbserver on %s\n",
                    gdbstub);
            exit(EXIT_FAILURE);
        }
        gdb_handlesig(cpu, 0);
    }
    cpu_loop(env);
    /* never exits */
    return 0;
}
