# CRUN运行容器
> crun是一个高效且低内存需求的OCI runtime实现。它是完全用c语言编写的。<br>
> crun实现满足 OCI Container Runtime specifications (https://github.com/opencontainers/runtime-spec).

### 代码分析
- [入口](https://github.com/containers/crun/blob/main/src/crun.c)
```diff
struct commands_s
{
  int value;
  const char *name;
  int (*handler) (struct crun_global_arguments *, int, char **, libcrun_error_t *);
};

struct commands_s commands[] = { { COMMAND_CREATE, "create", crun_command_create },
                                 { COMMAND_DELETE, "delete", crun_command_delete },
                                 { COMMAND_EXEC, "exec", crun_command_exec },
                                 { COMMAND_LIST, "list", crun_command_list },
                                 { COMMAND_KILL, "kill", crun_command_kill },
                                 { COMMAND_PS, "ps", crun_command_ps },
                                 { COMMAND_RUN, "run", crun_command_run },
                                 { COMMAND_SPEC, "spec", crun_command_spec },
                                 { COMMAND_START, "start", crun_command_start },
                                 { COMMAND_STATE, "state", crun_command_state },
                                 { COMMAND_UPDATE, "update", crun_command_update },
                                 { COMMAND_PAUSE, "pause", crun_command_pause },
                                 { COMMAND_UNPAUSE, "resume", crun_command_unpause },
#ifdef HAVE_CRIU
                                 { COMMAND_CHECKPOINT, "checkpoint", crun_command_checkpoint },
                                 { COMMAND_RESTORE, "restore", crun_command_restore },
#endif
                                 {
                                     0,
                                 } };
                                 
int
main (int argc, char **argv)
{
  libcrun_error_t err = NULL;
  int ret, first_argument = 0;

  argp_program_version_hook = print_version;
#ifdef HAVE_LIBKRUN
  if (strcmp (basename (argv[0]), "krun") == 0)
    {
      arguments.handler = "krun";
    }
#endif

  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, &first_argument, &arguments);

  command = get_command (argv[first_argument]);
  if (command == NULL)
    libcrun_fail_with_error (0, "unknown command %s", argv[first_argument]);

  if (arguments.debug)
    libcrun_set_verbosity (LIBCRUN_VERBOSITY_WARNING);

+ // 执行对应的操作函数
  ret = command->handler (&arguments, argc - first_argument, argv + first_argument, &err);
  if (ret && err)
    libcrun_fail_with_error (err->status, "%s", err->msg);
  return ret;
}
```

- crun_command_create
```diff
static struct argp_option options[]
    = { { "bundle", 'b', "DIR", 0, "container bundle (default \".\")", 0 },
        { "config", 'f', "FILE", 0, "override the config file name", 0 },
        { "console-socket", OPTION_CONSOLE_SOCKET, "SOCK", 0,
          "path to a socket that will receive the ptmx end of the tty", 0 },
        { "preserve-fds", OPTION_PRESERVE_FDS, "N", 0, "pass additional FDs to the container", 0 },
        { "no-pivot", OPTION_NO_PIVOT, 0, 0, "do not use pivot_root", 0 },
        { "pid-file", OPTION_PID_FILE, "FILE", 0, "where to write the PID of the container", 0 },
        { "no-subreaper", OPTION_NO_SUBREAPER, 0, 0, "do not create a subreaper process", 0 },
        { "no-new-keyring", OPTION_NO_NEW_KEYRING, 0, 0, "keep the same session key", 0 },
        {
            0,
        } };

int
crun_command_create (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg = 0, ret;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_free char *bundle_cleanup = NULL;
  cleanup_free char *config_file_cleanup = NULL;

  crun_context.preserve_fds = 0;
  /* Check if global handler is configured and pass it down to crun context */
  crun_context.handler = global_args->handler;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &crun_context);

  crun_assert_n_args (argc - first_arg, 1, 1);

  /* Make sure the config is an absolute path before changing the directory.  */
  if ((strcmp ("config.json", config_file) != 0))
    {
      if (config_file[0] != '/')
        {
          config_file_cleanup = realpath (config_file, NULL);
          if (config_file_cleanup == NULL)
            libcrun_fail_with_error (errno, "realpath `%s` failed", config_file);
          config_file = config_file_cleanup;
          crun_context.config_file = config_file;
        }
    }

+ // bundle路径必须是绝对路径
  /* Make sure the bundle is an absolute path.  */
  if (bundle == NULL)
    bundle = bundle_cleanup = getcwd (NULL, 0);
  else
    {
      if (bundle[0] != '/')
        {
          bundle_cleanup = realpath (bundle, NULL);
          if (bundle_cleanup == NULL)
            libcrun_fail_with_error (errno, "realpath `%s` failed", bundle);
          bundle = bundle_cleanup;
        }

      if (chdir (bundle) < 0)
        libcrun_fail_with_error (errno, "chdir `%s` failed", bundle);
    }

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  container = libcrun_container_load_from_file (config_file, err);
  if (container == NULL)
    libcrun_fail_with_error (0, "error loading config.json");

  crun_context.bundle = bundle;
  if (getenv ("LISTEN_FDS"))
    crun_context.preserve_fds += strtoll (getenv ("LISTEN_FDS"), NULL, 10);

+ // // 通过spec和上下文，创建一个容器
  return libcrun_container_create (&crun_context, container, 0, err);
}
```


** crun_command_create -> init_libcrun_context
```diff
struct libcrun_context_s
{
  const char *state_root;
  const char *id;
  const char *bundle;
  const char *config_file;
  const char *config_file_content;
  const char *console_socket;
  const char *pid_file;
  const char *notify_socket;
  const char *handler;
  int preserve_fds;

  crun_output_handler output_handler;
  void *output_handler_arg;

  int fifo_exec_wait_fd;

  bool systemd_cgroup;
  bool detach;
  bool no_subreaper;
  bool no_new_keyring;
  bool force_no_cgroup;
  bool no_pivot;

  int (*exec_func) (void *container, void *arg, const char *pathname, char *const argv[]);
  void *exec_func_arg;
};

+ // 定义libcrun_context_t
typedef struct libcrun_context_s libcrun_context_t;

int
init_libcrun_context (libcrun_context_t *con, const char *id, struct crun_global_arguments *glob, libcrun_error_t *err)
{
  int ret;

  con->id = id;
  con->state_root = glob->root;
  con->systemd_cgroup = glob->option_systemd_cgroup;
  con->force_no_cgroup = glob->option_force_no_cgroup;
  con->notify_socket = getenv ("NOTIFY_SOCKET");
  con->fifo_exec_wait_fd = -1;

  ret = libcrun_init_logging (&con->output_handler, &con->output_handler_arg, id, glob->log, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (glob->log_format)
    {
      ret = libcrun_set_log_format (glob->log_format, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (con->bundle == NULL)
    con->bundle = ".";

  if (con->config_file == NULL)
    con->config_file = "./config.json";

  return 0;
}
```

- crun_command_create -> libcrun_container_load_from_file
> 解析config.json，照oci spec规范load进runtime_spec_schema_config_schema(container->container_def)，返回libcrun_container_t结构
```diff
+ //container的结构定义，包含了schema和context
struct libcrun_container_s
{
  /* Container parsed from the runtime json file.  */
  runtime_spec_schema_config_schema *container_def;

  uid_t host_uid;
  gid_t host_gid;

  uid_t container_uid;
  gid_t container_gid;

  bool use_intermediate_userns;

  void *private_data;
  struct libcrun_context_s *context;
};

+ // 定义libcrun_container_t
typedef struct libcrun_container_s libcrun_container_t;


+ // oci runtime spec的schema定义
typedef struct {
    char *oci_version;

    runtime_spec_schema_config_schema_hooks *hooks;

    json_map_string_string *annotations;

    char *hostname;

    runtime_spec_schema_defs_mount **mounts;
    size_t mounts_len;

    runtime_spec_schema_config_schema_root *root;

    runtime_spec_schema_config_schema_process *process;

    runtime_spec_schema_config_linux *linux;

    runtime_spec_schema_config_solaris *solaris;

    runtime_spec_schema_config_windows *windows;

    runtime_spec_schema_config_vm *vm;

    yajl_val _residual;
}
runtime_spec_schema_config_schema;


libcrun_container_t *
libcrun_container_load_from_file (const char *path, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *container_def;
  cleanup_free char *oci_error = NULL;
  container_def = runtime_spec_schema_config_schema_parse_file (path, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load `%s`: %s", path, oci_error);
      return NULL;
    }
  return make_container (container_def);
}

runtime_spec_schema_config_schema *
runtime_spec_schema_config_schema_parse_file (const char *filename, const struct parser_context *ctx, parser_error *err)
{
    runtime_spec_schema_config_schema *ptr = NULL;
    size_t filesize;
    __auto_free char *content = NULL;

    if (filename == NULL || err == NULL)
      return NULL;

    *err = NULL;
    content = read_file (filename, &filesize);
    if (content == NULL)
      {
        if (asprintf (err, "cannot read the file: %s", filename) < 0)
            *err = strdup ("error allocating memory");
        return NULL;
      }
    ptr = runtime_spec_schema_config_schema_parse_data (content, ctx, err);
    return ptr;
}

static libcrun_container_t *
make_container (runtime_spec_schema_config_schema *container_def)
{
  libcrun_container_t *container = xmalloc0 (sizeof (*container));
  container->container_def = container_def;

  container->host_uid = geteuid ();
  container->host_gid = getegid ();

  container->use_intermediate_userns = need_intermediate_userns (container_def);

  return container;
}
```

### 创建容器
- crun_command_create -> libcrun_container_create
```diff
int
libcrun_container_create (libcrun_context_t *context, libcrun_container_t *container, unsigned int options,
                          libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  int container_ready_pipe[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int exec_fifo_fd = -1;
  
+  //为1表示，crun create 指令不阻塞，直接返回（只有crun run这个detach是0）
  context->detach = 1;

  container->context = context;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->process && def->process->terminal && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with create when a terminal is used");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

+ // 创建执行等待execfifo，在容器create完成后阻塞进程，等待命令执行
  exec_fifo_fd = libcrun_status_create_exec_fifo (context->state_root, context->id, err);
  if (UNLIKELY (exec_fifo_fd < 0))
    return exec_fifo_fd;

  context->fifo_exec_wait_fd = exec_fifo_fd;
  exec_fifo_fd = -1;

  if ((options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
    {
      ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
      if (UNLIKELY (ret < 0))
        return ret;
+     // container_ready_fd=-1
      ret = libcrun_container_run_internal (container, context, -1, err);
      if (UNLIKELY (ret < 0))
        force_delete_container_status (context, def);
      return ret;
    }

  ret = pipe (container_ready_pipe);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ready_pipe[0];
  pipefd1 = container_ready_pipe[1];

  ret = fork ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "fork");
  if (ret)
    {
      int exit_code;
      close_and_reset (&pipefd1);

      TEMP_FAILURE_RETRY (waitpid (ret, NULL, 0));

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &exit_code, sizeof (exit_code)));
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "waiting for container to be ready");
      if (ret > 0)
        {
          if (exit_code != 0)
            {
              libcrun_error_t tmp_err = NULL;
              libcrun_container_delete (context, def, context->id, true, &tmp_err);
              crun_error_release (err);
            }
          return -exit_code;
        }
      return 1;
    }

  /* forked process.  */
  ret = detach_process ();
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "detach process");

  ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
  if (UNLIKELY (ret < 0))
    libcrun_fail_with_error (errno, "copy config file");

  ret = libcrun_container_run_internal (container, context, pipefd1, err);
  if (UNLIKELY (ret < 0))
    {
      force_delete_container_status (context, def);
      libcrun_error ((*err)->status, "%s", (*err)->msg);
      crun_set_output_handler (log_write_to_stderr, NULL, false);
    }

  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  exit (ret ? EXIT_FAILURE : 0);
}
```

- crun_command_create -> libcrun_container_create -> libcrun_container_run_internal
```diff
static int
libcrun_container_run_internal (libcrun_container_t *container, libcrun_context_t *context, int container_ready_fd,
                                libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  int ret;
  pid_t pid;
  int detach = context->detach;
  cleanup_free char *cgroup_path = NULL;
  cleanup_free char *scope = NULL;
  cleanup_close int terminal_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_close int sync_socket = -1;
  cleanup_close int notify_socket = -1;
  cleanup_close int socket_pair_0 = -1;
  cleanup_close int socket_pair_1 = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_close int console_socket_fd = -1;
  cleanup_close int hooks_out_fd = -1;
  cleanup_close int hooks_err_fd = -1;
  cleanup_close int own_seccomp_receiver_fd = -1;
  cleanup_close int seccomp_notify_fd = -1;
  const char *seccomp_notify_plugins = NULL;
  int cgroup_mode, cgroup_manager;
  char created[35];
  uid_t root_uid = -1;
  gid_t root_gid = -1;
  struct container_entrypoint_s container_args = {
    .container = container,
    .context = context,
    .terminal_socketpair = { -1, -1 },
    .console_socket_fd = -1,
    .hooks_out_fd = -1,
    .hooks_err_fd = -1,
    .seccomp_receiver_fd = -1,
    .exec_func = context->exec_func,
    .exec_func_arg = context->exec_func_arg,
  };

  if (def->hooks
      && (def->hooks->prestart_len || def->hooks->poststart_len || def->hooks->create_runtime_len
          || def->hooks->create_container_len || def->hooks->start_container_len))
    {
      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
      container_args.hooks_out_fd = hooks_out_fd;
      container_args.hooks_err_fd = hooks_err_fd;
    }

  container->context = context;

  if (! detach || context->notify_socket)
    {
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "set child subreaper");
    }

  if (! context->no_new_keyring)
    {
      const char *label = NULL;

      if (def->process)
        label = def->process->selinux_label;

      ret = libcrun_create_keyring (container->context->id, label, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      container_args.has_terminal_socket_pair = 1;
      ret = create_socket_pair (container_args.terminal_socketpair, err);
      if (UNLIKELY (ret < 0))
        return crun_error_wrap (err, "create terminal socket");

      socket_pair_0 = container_args.terminal_socketpair[0];
      socket_pair_1 = container_args.terminal_socketpair[1];
    }

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (def->linux && (def->linux->seccomp || find_annotation (container, "run.oci.seccomp_bpf_data")))
    {
      ret = open_seccomp_output (context->id, &seccomp_fd, false, context->state_root, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
  container_args.seccomp_fd = seccomp_fd;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &container_args.seccomp_receiver_fd, &own_seccomp_receiver_fd,
                                     &seccomp_notify_plugins, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  if (context->console_socket)
    {
      console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
      if (UNLIKELY (console_socket_fd < 0))
        return crun_error_wrap (err, "open console socket");
      container_args.console_socket_fd = console_socket_fd;
    }

  cgroup_mode = libcrun_get_cgroup_mode (err);
  if (UNLIKELY (cgroup_mode < 0))
    return cgroup_mode;

+ // 运行一个linux容器，容器运行后，调用container_init函数初始化
  pid = libcrun_run_linux_container (container, container_init, &container_args, &sync_socket, err);
  if (UNLIKELY (pid < 0))
    return pid;

  if (context->fifo_exec_wait_fd < 0 && context->notify_socket)
    {
      /* Do not open the notify socket here on "create".  "start" will take care of it.  */
      ret = get_notify_fd (context, container, &notify_socket, err);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  if (container_args.terminal_socketpair[1] >= 0)
    close_and_reset (&socket_pair_1);

  cgroup_manager = CGROUP_MANAGER_CGROUPFS;
  if (context->systemd_cgroup)
    cgroup_manager = CGROUP_MANAGER_SYSTEMD;
  else if (context->force_no_cgroup)
    cgroup_manager = CGROUP_MANAGER_DISABLED;

  /* If we are root (either on the host or in a namespace), then chown the cgroup to root in the container user
   * namespace.  */
  get_root_in_the_userns (def, container->host_uid, container->host_gid, &root_uid, &root_gid);

  {
    struct libcrun_cgroup_args cg = {
      .resources = def->linux ? def->linux->resources : NULL,
      .annotations = def->annotations,
      .cgroup_mode = cgroup_mode,
      .path = &cgroup_path,
      .scope = &scope,
      .cgroup_path = def->linux ? def->linux->cgroups_path : "",
      .manager = cgroup_manager,
      .pid = pid,
      .root_uid = root_uid,
      .root_gid = root_gid,
      .id = context->id,
      .systemd_subgroup = find_systemd_subgroup (container, cgroup_mode),
      .delegate_cgroup = find_delegate_cgroup (container),
    };

    ret = libcrun_cgroup_enter (&cg, err);
    if (UNLIKELY (ret < 0))
      return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
  }

  /* sync send own pid.  */
  ret = TEMP_FAILURE_RETRY (write (sync_socket, &pid, sizeof (pid)));
  if (UNLIKELY (ret != sizeof (pid)))
    {
      if (ret >= 0)
        errno = 0;
      crun_make_error (err, errno, "write to sync socket");
      return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  /* sync 1.  */
  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  /* sync 2.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  /* The container is waiting that we write back.  In this phase we can launch the
     prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      ret = do_hooks (def, pid, context->id, false, NULL, "created", (hook **) def->hooks->prestart,
                      def->hooks->prestart_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret != 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }
  if (def->hooks && def->hooks->create_runtime_len)
    {
      ret = do_hooks (def, pid, context->id, false, NULL, "created", (hook **) def->hooks->create_runtime,
                      def->hooks->create_runtime_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret != 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  if (seccomp_fd >= 0)
    {
      unsigned int seccomp_gen_options = 0;
      const char *annotation;

      annotation = find_annotation (container, "run.oci.seccomp_fail_unknown_syscall");
      if (annotation && strcmp (annotation, "0") != 0)
        seccomp_gen_options = LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL;

      if ((annotation = find_annotation (container, "run.oci.seccomp_bpf_data")) != NULL)
        {
          cleanup_free char *bpf_data = NULL;
          size_t size = 0;
          size_t in_size;
          int consumed;

          in_size = strlen (annotation);
          bpf_data = xmalloc (in_size + 1);

          consumed = base64_decode (annotation, in_size, bpf_data, in_size, &size);
          if (UNLIKELY (consumed != (int) in_size))
            {
              ret = crun_make_error (err, 0, "invalid seccomp BPF data");
              return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
            }

          ret = safe_write (seccomp_fd, bpf_data, (ssize_t) size);
          if (UNLIKELY (ret < 0))
            {
              crun_make_error (err, 0, "write to seccomp fd");
              return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
            }
        }
      else
        {
          ret = libcrun_generate_seccomp (container, seccomp_fd, seccomp_gen_options, err);
          if (UNLIKELY (ret < 0))
            return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
        }
      close_and_reset (&seccomp_fd);
    }

  /* sync 3.  */
  ret = sync_socket_send_sync (sync_socket, true, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      terminal_fd = receive_fd_from_socket (socket_pair_0, err);
      if (UNLIKELY (terminal_fd < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

      close_and_reset (&socket_pair_0);

      ret = libcrun_setup_terminal_ptmx (terminal_fd, &orig_terminal, err);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  /* sync 4.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  ret = close_and_reset (&sync_socket);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  get_current_timestamp (created);
  ret = write_container_status (container, context, pid, cgroup_path, scope, created, err);
  if (UNLIKELY (ret < 0))
    return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

  /* Run poststart hooks here only if the container is created using "run".  For create+start, the
     hooks will be executed as part of the start command.  */
  if (context->fifo_exec_wait_fd < 0 && def->hooks && def->hooks->poststart_len)
    {
      ret = do_hooks (def, pid, context->id, true, NULL, "running", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
  if (own_seccomp_receiver_fd >= 0)
    {
      seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
      if (UNLIKELY (seccomp_notify_fd < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);

      ret = close_and_reset (&own_seccomp_receiver_fd);
      if (UNLIKELY (ret < 0))
        return cleanup_watch (context, def, cgroup_path, cgroup_mode, pid, sync_socket, terminal_fd, err);
    }

  ret = wait_for_process (pid, context, terminal_fd, notify_socket, container_ready_fd, seccomp_notify_fd,
                          seccomp_notify_plugins, err);
  if (! context->detach)
    {
      libcrun_error_t tmp_err = NULL;
      cleanup_watch (context, def, cgroup_path, cgroup_mode, 0, sync_socket, terminal_fd, &tmp_err);
      crun_error_release (&tmp_err);
    }

  return ret;
}
```

- [libcrun_run_linux_container](https://github.com/containers/crun/blob/main/src/libcrun/linux.c)
```diff
pid_t
libcrun_run_linux_container (libcrun_container_t *container, container_entrypoint_t entrypoint, void *args,
                             int *sync_socket_out, libcrun_error_t *err)
{
  __attribute__ ((cleanup (cleanup_free_init_statusp))) struct init_status_s init_status;
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int sync_socket_container = -1;
  char *notify_socket_env = NULL;
  cleanup_close int sync_socket_host = -1;
  __attribute__ ((unused)) cleanup_close int restore_pidns = -1;
  int first_clone_args = 0;
  const char failure = 1;
  const char success = 0;
  int sync_socket[2];
  pid_t pid;
  size_t i;
  int ret;
+ // 初始化命名空间,打开命名空间fd
  ret = configure_init_status (&init_status, container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  get_private_data (container)->unshare_flags = init_status.all_namespaces;
#if CLONE_NEWCGROUP
  /* cgroup will be unshared later.  Once the process is in the correct cgroup.  */
  init_status.all_namespaces &= ~CLONE_NEWCGROUP;
#endif

  ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "socketpair");

  sync_socket_host = sync_socket[0];
  sync_socket_container = sync_socket[1];

#ifdef HAVE_SYSTEMD
  if (def->root)
    {
      ret = do_notify_socket (container, def->root->path, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }
#endif

  get_uid_gid_from_def (container->container_def, &container->container_uid, &container->container_gid);

  /* This must be done before we enter a user namespace.  */
  if (def->process)
    {
      ret = libcrun_set_rlimits (def->process->rlimits, def->process->rlimits_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_oom (container, err);
  if (UNLIKELY (ret < 0))
    return ret;

  /* If a new user namespace must be created, but there are other namespaces to join, then delay
     the userns creation after the namespaces are joined.  */
  init_status.delayed_userns_create
      = (init_status.all_namespaces & CLONE_NEWUSER) && init_status.userns_index < 0 && init_status.fd_len > 0;

  /* Check if special handling is required to join the namespaces.  */
  for (i = 0; i < init_status.fd_len; i++)
    {
      switch (init_status.value[i])
        {
        case CLONE_NEWIPC:
          if (init_status.all_namespaces & CLONE_NEWUSER)
            init_status.join_ipcns = true;
          break;

        case CLONE_NEWPID:
          if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
            init_status.must_fork = true;
          else
            {
              init_status.join_pidns = true;
              init_status.idx_pidns_to_join_immediately = i;
              init_status.namespaces_to_unshare &= ~CLONE_NEWPID;
            }
          break;

        case CLONE_NEWTIME:
          if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
            init_status.must_fork = true;
          else
            {
              init_status.idx_timens_to_join_immediately = i;
              init_status.namespaces_to_unshare &= ~CLONE_NEWTIME;
            }
          break;
        }
    }

  /* Before attempting any setns() or unshare(), a clone() is required to not touch the caller context
     that can be used later on for running hooks.  */

  if ((init_status.namespaces_to_unshare & CLONE_NEWUSER) && init_status.fd_len == 0)
    {
      /* If a user namespace must be created and there are no other namespaces to join, create the userns alone.  */
      first_clone_args = CLONE_NEWUSER;
    }
  else if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
    {
      /* If it doesn't create a user namespace or need to join one, create the new requested namespaces now. */
      first_clone_args = init_status.namespaces_to_unshare & ~(CLONE_NEWTIME | CLONE_NEWCGROUP);
    }

  pid = syscall_clone (first_clone_args | SIGCHLD, NULL);
  if (UNLIKELY (pid < 0))
    return crun_make_error (err, errno, "clone");

  init_status.namespaces_to_unshare &= ~first_clone_args;

  /* Check if there are still namespaces that require a fork().  */
  if (init_status.namespaces_to_unshare & (CLONE_NEWPID | CLONE_NEWTIME))
    init_status.must_fork = true;

  if (pid)
    {
      cleanup_pid pid_t pid_to_clean = pid;

      ret = save_external_descriptors (container, pid, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = close_and_reset (&sync_socket_container);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "close");

      /* any systemd notify socket open_tree FD is pointless to keep around in the parent */
      close_and_reset (&(get_private_data (container)->notify_socket_tree_fd));

      if (init_status.idx_pidns_to_join_immediately >= 0 || init_status.idx_timens_to_join_immediately >= 0)
        {
          pid_t new_pid = 0;

          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &new_pid, sizeof (new_pid)));
          if (UNLIKELY (ret != sizeof (new_pid)))
            return crun_make_error (err, errno, "read pid from sync socket");

          /* Cleanup the first process.  */
          ret = TEMP_FAILURE_RETRY (waitpid (pid, NULL, 0));

          pid_to_clean = pid = new_pid;

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, &success, 1));
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if (init_status.delayed_userns_create)
        {
          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      if ((init_status.all_namespaces & CLONE_NEWUSER) && init_status.userns_index < 0)
        {
          ret = libcrun_set_usernamespace (container, pid, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, "1", 1));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "write to sync socket");
        }

      if (init_status.must_fork)
        {
          pid_t grandchild = 0;

          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;

          ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &grandchild, sizeof (grandchild)));
          if (UNLIKELY (ret < 0))
            return crun_make_error (err, errno, "read pid from sync socket");

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, &success, 1));
          if (UNLIKELY (ret < 0))
            return ret;

          /* Cleanup the first process.  */
          waitpid (pid, NULL, 0);

          pid_to_clean = pid = grandchild;
        }

      ret = expect_success_from_sync_socket (sync_socket_host, err);
      if (UNLIKELY (ret < 0))
        return ret;

      *sync_socket_out = get_and_reset (&sync_socket_host);

      pid_to_clean = 0;
      return pid;
    }

  /* Inside the container process.  */

  ret = close_and_reset (&sync_socket_host);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "close");

  /* Initialize the new process and make sure to join/create all the required namespaces.  */
  ret = init_container (container, sync_socket_container, &init_status, err);
  if (UNLIKELY (ret < 0))
    {
      ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &failure, 1));
      if (UNLIKELY (ret < 0))
        goto localfail;

      send_error_to_sync_socket_and_die (sync_socket_container, false, err);

    localfail:
      libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
      _exit (EXIT_FAILURE);
    }
  else
    {
      ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &success, 1));
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* Jump into the specified entrypoint.  */
  if (container->context->notify_socket)
    xasprintf (&notify_socket_env, "NOTIFY_SOCKET=%s/notify", container->context->notify_socket);

  entrypoint (args, notify_socket_env, sync_socket_container, err);

  /* ENTRYPOINT returns only on an error, fallback here: */
  if (*err)
    libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
  _exit (EXIT_FAILURE);
}
```
