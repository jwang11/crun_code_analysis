# crun_create容器
> crun是一个基于C语言编写的，高效且低内存需求的OCI runtime实现，<br>
> 符合OCI Container Runtime specifications (https://github.com/opencontainers/runtime-spec)。

### 主程序
```diff
- crun是标准的 命令 + global_opts + 子命令 + opts + args的结构
Usage: crun [OPTION...] COMMAND [OPTION...]

COMMANDS:
        checkpoint  - checkpoint a container
        create      - create a container
        delete      - remove definition for a container
        exec        - exec a command in a running container
        list        - list known containers
        kill        - send a signal to the container init process
        ps          - show the processes in the container
        restore     - restore a container
        run         - run a container
        spec        - generate a configuration file
        start       - start a container
        state       - output the state of a container
        pause       - pause all the processes in the container
        resume      - unpause the processes in the container
        update      - update container resource constraints

      --cgroup-manager=MANAGER   cgroup manager
      --debug                produce verbose output
      --log=FILE
      --log-format=FORMAT
      --root=DIR
      --rootless=VALUE
      --systemd-cgroup       use systemd cgroups
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

- [主命令入口](https://github.com/containers/crun/blob/main/src/crun.c)
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

- // 执行对应子命令的处理函数
  ret = command->handler (&arguments, argc - first_argument, argv + first_argument, &err);
  if (ret && err)
    libcrun_fail_with_error (err->status, "%s", err->msg);
  return ret;
}
```

### Creat子命令
```diff
- 对应执行命令行$crun create ID
 Usage: create [OPTION...] create [OPTION]... CONTAINER
 OCI runtime

  -b, --bundle=DIR           container bundle (default ".")
      --console-socket=SOCK  path to a socket that will receive the ptmx end of
                             the tty
  -f, --config=FILE          override the config file name
      --no-new-keyring       keep the same session key
      --no-pivot             do not use pivot_root
      --no-subreaper         do not create a subreaper process
      --pid-file=FILE        where to write the PID of the container
      --preserve-fds=N       pass additional FDs to the container
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```
- Create子命令入口***crun_command_create***
```diff
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

- // 根据命令行参数初始化上线文，包括state_root路径，cgroup管理器，fifo_exec等
+ ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

- // 根据oci runtime规范生成container对象。
- // 解析config.json，转变为runtime_spec_schema_config_schema对象，放入container->container_def，返回container
  container = libcrun_container_load_from_file (config_file, err);
  if (container == NULL)
    libcrun_fail_with_error (0, "error loading config.json");

- // 指定bundle的绝对路径
  crun_context.bundle = bundle;
  if (getenv ("LISTEN_FDS"))
    crun_context.preserve_fds += strtoll (getenv ("LISTEN_FDS"), NULL, 10);

- // 根据container对象和运行contex，创建容器
  return libcrun_container_create (&crun_context, container, 0, err);
}
```
> crun_command_create -> init_libcrun_context
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

- // 定义libcrun_context_t
+ typedef struct libcrun_context_s libcrun_context_t;

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

> crun_command_create -> libcrun_container_load_from_file
```diff
- //container的结构定义
struct libcrun_container_s
{
  /* Container parsed from the runtime json file.  */
+ runtime_spec_schema_config_schema *container_def;

  uid_t host_uid;
  gid_t host_gid;

  uid_t container_uid;
  gid_t container_gid;

- // 容器需要一个非root的user
  bool use_intermediate_userns;

  void *private_data;
+ struct libcrun_context_s *context;
};

- // 定义libcrun_container_t
typedef struct libcrun_container_s libcrun_container_t;

- // oci runtime spec的schema定义
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
+ container_def = runtime_spec_schema_config_schema_parse_file (path, NULL, &oci_error);
  if (container_def == NULL)
    {
      crun_make_error (err, 0, "load `%s`: %s", path, oci_error);
      return NULL;
    }
+ return make_container (container_def);
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
```

>> libcrun_container_load_from_file -> make_container
```diff
static libcrun_container_t *
make_container (runtime_spec_schema_config_schema *container_def)
{
  libcrun_container_t *container = xmalloc0 (sizeof (*container));
  container->container_def = container_def;

- // 设置host的uid和gid
  container->host_uid = geteuid ();
  container->host_gid = getegid ();

  container->use_intermediate_userns = need_intermediate_userns (container_def);

  return container;
}

/*
  Create an intermediate user namespace if there is a single id mapped
  inside of the container user namespace and the container wants to run
  with a different UID/GID than root.
*/
static bool
need_intermediate_userns (runtime_spec_schema_config_schema *def)
{
  runtime_spec_schema_config_schema_process *process = def->process;
  uid_t container_uid;
  gid_t container_gid;
  container_uid = process->user ? process->user->uid : 0;
  container_gid = process->user ? process->user->gid : 0;

  if (container_uid == 0 && container_gid == 0)
    return false;

  if (def->linux == NULL)
    return false;

  if (def->linux->uid_mappings_len != 1 || def->linux->gid_mappings_len != 1)
    return false;

  if (def->linux->uid_mappings[0]->size != 1 || def->linux->gid_mappings[0]->size != 1)
    return false;

  if (def->linux->uid_mappings[0]->container_id == container_uid
      && def->linux->gid_mappings[0]->container_id == container_gid)
    return false;

  return true;
}
```

### 创建容器
```diff
- 根据options里是否设置LIBCRUN_RUN_OPTIONS_PREFORK有两条途径，差别在host端多fork了一次。
- 目前只有python-crun实现里用到了LIBCRUN_RUN_OPTIONS_PREFORK
```
- ***crun_command_create -> libcrun_container_create***
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
 
- // crun create本身没有detach命令行参数，这里强制设置为1
- context->detach = 1;

  container->context = context;

  if (def->oci_version && strstr (def->oci_version, "1.0") == NULL)
    return crun_make_error (err, 0, "unknown version specified");

  ret = check_config_file (def, context, err);
  if (UNLIKELY (ret < 0))
    return ret;

- // 如果terminal=true，在create的时候必须提供console_socket。（run的时候可以不提供，crun内部会创建）
  if (def->process && def->process->terminal && context->console_socket == NULL)
    return crun_make_error (err, 0, "use --console-socket with create when a terminal is used");

  ret = libcrun_status_check_directories (context->state_root, context->id, err);
  if (UNLIKELY (ret < 0))
    return ret;

- // 创建执行等待execfifo，在容器create完成后阻塞进程，等待命令执行
+ exec_fifo_fd = libcrun_status_create_exec_fifo (context->state_root, context->id, err);
  if (UNLIKELY (exec_fifo_fd < 0))
    return exec_fifo_fd;

  context->fifo_exec_wait_fd = exec_fifo_fd;
  exec_fifo_fd = -1;

- // 按照LIBCRUN_RUN_OPTIONS_PREFORK是否设置有两条路
  if ((options & LIBCRUN_RUN_OPTIONS_PREFORK) == 0)
- // 没有LIBCRUN_RUN_OPTIONS_PREFORK  
    {
      ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);
      if (UNLIKELY (ret < 0))
        return ret;
-     // 这里参数container_ready_fd=-1
     ret = libcrun_container_run_internal (container, context, -1, err);
      if (UNLIKELY (ret < 0))
        force_delete_container_status (context, def);
      return ret;
    }

- // 有LIBCRUN_RUN_OPTIONS_PREFORK
  ret = pipe (container_ready_pipe);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ready_pipe[0];
  pipefd1 = container_ready_pipe[1];

  ret = fork ();
  if (ret)
    {
      int exit_code;
      close_and_reset (&pipefd1);

      TEMP_FAILURE_RETRY (waitpid (ret, NULL, 0));

      ret = TEMP_FAILURE_RETRY (read (pipefd0, &exit_code, sizeof (exit_code)));
      return 1;
    }

  /* forked process.  */
  ret = detach_process ();

  ret = libcrun_copy_config_file (context->id, context->state_root, context->config_file, context->config_file_content, err);

  ret = libcrun_container_run_internal (container, context, pipefd1, err);

  TEMP_FAILURE_RETRY (write (pipefd1, &ret, sizeof (ret)));
  exit (ret ? EXIT_FAILURE : 0);
}
```

- ***crun_command_create -> libcrun_container_create -> libcrun_container_run_internal***
```diff
- 从这里才是真正开始create容器。容器里最麻烦的是设置namespace（有些unshare，有些join，还有些不能同时进行），需要多次fork和进程间同步，过程比较复杂
```
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

- // 检查config.json的annotation是否定义了stdout,stderr
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

- // 如果不是detach或者systemd指定notify_socket，使当前进程成为subreaper，来收容孤儿进程。注意，运行crun create时，detach=1
  if (! detach || context->notify_socket)
    {
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "set child subreaper");
    }

- // 默认是为每个进程创建keyring，除非有no_new_keyring
  if (! context->no_new_keyring)
    {
      const char *label = NULL;

      if (def->process)
        label = def->process->selinux_label;

      ret = libcrun_create_keyring (container->context->id, label, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

- // 如果没有console_socket而且不是detach模式，就创建一对socket_pair做console输出。
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

- // 得到seccomp.bpf文件的fd
  if (def->linux && (def->linux->seccomp || find_annotation (container, "run.oci.seccomp_bpf_data")))
    {
      ret = open_seccomp_output (context->id, &seccomp_fd, false, context->state_root, err);
    }
  container_args.seccomp_fd = seccomp_fd;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &container_args.seccomp_receiver_fd, &own_seccomp_receiver_fd,
                                     &seccomp_notify_plugins, err);
    }

- // 如果指定console_socket，打开得到fd
  if (context->console_socket)
    {
      console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
      container_args.console_socket_fd = console_socket_fd;
    }

- // 得到cgroup模式
  cgroup_mode = libcrun_get_cgroup_mode (err);

- // 运行一个linux容器，注意参数entrypoint=container_init，返回grand child的PID以及sync_socket
+ pid = libcrun_run_linux_container (container, container_init, &container_args, &sync_socket, err);

- // 如果没有定义fifo_exec，同时systemd指定notify_socket
  if (context->fifo_exec_wait_fd < 0 && context->notify_socket)
    {
      /* Do not open the notify socket here on "create".  "start" will take care of it.  */
      ret = get_notify_fd (context, container, &notify_socket, err);
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
  }

  /* sync send own pid.  */
  ret = TEMP_FAILURE_RETRY (write (sync_socket, &pid, sizeof (pid)));

  /* sync 1.  */
  ret = sync_socket_send_sync (sync_socket, true, err);

  /* sync 2.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);

  /* The container is waiting that we write back.  In this phase we can launch the
     prestart hooks.  */
  if (def->hooks && def->hooks->prestart_len)
    {
      ret = do_hooks (def, pid, context->id, false, NULL, "created", (hook **) def->hooks->prestart,
                      def->hooks->prestart_len, hooks_out_fd, hooks_err_fd, err);
    }
  if (def->hooks && def->hooks->create_runtime_len)
    {
      ret = do_hooks (def, pid, context->id, false, NULL, "created", (hook **) def->hooks->create_runtime,
                      def->hooks->create_runtime_len, hooks_out_fd, hooks_err_fd, err);
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
          ret = safe_write (seccomp_fd, bpf_data, (ssize_t) size);
        }
      else
        {
          ret = libcrun_generate_seccomp (container, seccomp_fd, seccomp_gen_options, err);
        }
      close_and_reset (&seccomp_fd);
    }

  /* sync 3.  */
  ret = sync_socket_send_sync (sync_socket, true, err);

- // 得到container端传过来的pty masterfd，设置好状态
  if (def->process && def->process->terminal && ! detach && context->console_socket == NULL)
    {
      terminal_fd = receive_fd_from_socket (socket_pair_0, err);
      close_and_reset (&socket_pair_0);
      ret = libcrun_setup_terminal_ptmx (terminal_fd, &orig_terminal, err);
    }

  /* sync 4.  */
  ret = sync_socket_wait_sync (context, sync_socket, false, err);
  ret = close_and_reset (&sync_socket);

  get_current_timestamp (created);

- // 修改container状态到“created”
+ ret = write_container_status (container, context, pid, cgroup_path, scope, created, err);
  /* Run poststart hooks here only if the container is created using "run".  For create+start, the
  
     hooks will be executed as part of the start command.  */
  if (context->fifo_exec_wait_fd < 0 && def->hooks && def->hooks->poststart_len)
    {
      ret = do_hooks (def, pid, context->id, true, NULL, "running", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, err);
    }

  /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
  if (own_seccomp_receiver_fd >= 0)
    {
      seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
      ret = close_and_reset (&own_seccomp_receiver_fd);
    }

+  ret = wait_for_process (pid, context, terminal_fd, notify_socket, container_ready_fd, seccomp_notify_fd,
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
- linux container的初始化总体分为host端和container端，container端是host端fork出来，是父子关系
- container端为了正确设置namespace还会fork一次
- 返回grand child的PID
```

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
- // 把namespace的需求做分类
+ ret = configure_init_status (&init_status, container, err);

+ // 把unshare的namespace信息放入priviate data
  get_private_data (container)->unshare_flags = init_status.all_namespaces;
#if CLONE_NEWCGROUP
  /* cgroup will be unshared later.  Once the process is in the correct cgroup.  */
  init_status.all_namespaces &= ~CLONE_NEWCGROUP;
#endif

- // 建立双工的socketpair，用来host <-> container通信
+ ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket);
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
- // 获取config.json指定的process里的uid，gid，默认是0，代表root
+ get_uid_gid_from_def (container->container_def, &container->container_uid, &container->container_gid);

  /* This must be done before we enter a user namespace.  */
  if (def->process)
    {
      ret = libcrun_set_rlimits (def->process->rlimits, def->process->rlimits_len, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_set_oom (container, err);

- // 如果要新创建NEWUSER namespace，同时还有需要join的其它namespac。次序是先join，后创建NEWUSER。
  /* If a new user namespace must be created, but there are other namespaces to join, then delay
     the userns creation after the namespaces are joined.  */
  init_status.delayed_userns_create
      = (init_status.all_namespaces & CLONE_NEWUSER) && init_status.userns_index < 0 && init_status.fd_len > 0;

- // 对需要特殊处理的namespace做标注 - NEWIPC，NEWPID和NEWTIME
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
-         // 如果没有NEWUSER，而有NEWPID需要join，must_fork=true        
          if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
+           init_status.must_fork = true;
          else
            {
              init_status.join_pidns = true;
-             // 如果有NEWUSER，同时有NEWPID需要join
+             init_status.idx_pidns_to_join_immediately = i;
              init_status.namespaces_to_unshare &= ~CLONE_NEWPID;
            }
          break;

        case CLONE_NEWTIME:
          if ((init_status.all_namespaces & CLONE_NEWUSER) == 0)
            init_status.must_fork = true;
          else
            {
  -           // 如果有NEWUSER，同时有NEWTIME需要join
  +           init_status.idx_timens_to_join_immediately = i;
              init_status.namespaces_to_unshare &= ~CLONE_NEWTIME;
            }
          break;
        }
    }

  /* Before attempting any setns() or unshare(), a clone() is required to not touch the caller context
     that can be used later on for running hooks.  */

- //如果要新的NEWUSER namespace，第一次fork只处理NEWUSER；如果是join提供path的NEWUSER，处理除了(CLONE_NEWTIME | CLONE_NEWCGROUP)之外的namespace
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
    
- // 第一次fork
  pid = syscall_clone (first_clone_args | SIGCHLD, NULL);

  init_status.namespaces_to_unshare &= ~first_clone_args;

- // 检查是否还有其它namespace需要单独fork，例如(CLONE_NEWPID | CLONE_NEWTIME)
  /* Check if there are still namespaces that require a fork().  */
  if (init_status.namespaces_to_unshare & (CLONE_NEWPID | CLONE_NEWTIME))
    init_status.must_fork = true;

  if (pid)
    {
-     // host端    
      cleanup_pid pid_t pid_to_clean = pid;

      ret = save_external_descriptors (container, pid, err);
      ret = close_and_reset (&sync_socket_container);
      
      /* any systemd notify socket open_tree FD is pointless to keep around in the parent */
      close_and_reset (&(get_private_data (container)->notify_socket_tree_fd));

      if (init_status.idx_pidns_to_join_immediately >= 0 || init_status.idx_timens_to_join_immediately >= 0)
        {
          pid_t new_pid = 0;

          ret = expect_success_from_sync_socket (sync_socket_host, err);
          if (UNLIKELY (ret < 0))
            return ret;

-         // 和container端通信，得到new_pid
+         ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &new_pid, sizeof (new_pid)));

-         // 等container端第一个子进程结束
          /* Cleanup the first process.  */
+         ret = TEMP_FAILURE_RETRY (waitpid (pid, NULL, 0));

          pid_to_clean = pid = new_pid;

-         // 和container通信，确保new_pid正常工作
+         ret = TEMP_FAILURE_RETRY (write (sync_socket_host, &success, 1));
        }

-     // 如果有delayed_userns_create标志，要等container端join好namespace后再处理user namespace
      if (init_status.delayed_userns_create)
        {
+         ret = expect_success_from_sync_socket (sync_socket_host, err);

        }

-     // set NEWUSER namespace
      if ((init_status.all_namespaces & CLONE_NEWUSER) && init_status.userns_index < 0)
        {
+         ret = libcrun_set_usernamespace (container, pid, err);

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, "1", 1));
        }

-     // 检查是否需要再次fork
      if (init_status.must_fork)
        {
          pid_t grandchild = 0;

          ret = expect_success_from_sync_socket (sync_socket_host, err);

-         // 得到grandchild的PID
          ret = TEMP_FAILURE_RETRY (read (sync_socket_host, &grandchild, sizeof (grandchild)));

          ret = TEMP_FAILURE_RETRY (write (sync_socket_host, &success, 1));

-         // 等待new_pid子进程退出
          /* Cleanup the first process.  */
+          waitpid (pid, NULL, 0);

-         // container端目前是grandchild
          pid_to_clean = pid = grandchild;
        }

      ret = expect_success_from_sync_socket (sync_socket_host, err);

-     // 把host端的socket通过参数传递到libcrun_run_linux_container函数外面，由libcrun_container_run_internal继续处理
+     *sync_socket_out = get_and_reset (&sync_socket_host);

      pid_to_clean = 0;
      return pid;
    }

- // 这里是container端了
  /* Inside the container process.  */

  ret = close_and_reset (&sync_socket_host);

  /* Initialize the new process and make sure to join/create all the required namespaces.  */
  ret = init_container (container, sync_socket_container, &init_status, err);
    {
      ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &success, 1));
    }

  /* Jump into the specified entrypoint.  */
  if (container->context->notify_socket)
    xasprintf (&notify_socket_env, "NOTIFY_SOCKET=%s/notify", container->context->notify_socket);

- // 执行entrypont的命令，也就是container_init
+ entrypoint (args, notify_socket_env, sync_socket_container, err);

  /* ENTRYPOINT returns only on an error, fallback here: */
  if (*err)
    libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
  _exit (EXIT_FAILURE);
}
```

> ***libcrun_run_linux_container -> configure_init_status***
```diff
- 处理config.json里的namespace，分为unshare(新建namespace)和share(join已经存在的namespace）两类
```
```diff
static int
configure_init_status (struct init_status_s *ns, libcrun_container_t *container, libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  size_t i;

  for (i = 0; i < MAX_NAMESPACES + 1; i++)
    ns->fd[i] = -1;

  ns->fd_len = 0;
  ns->all_namespaces = 0;
  ns->namespaces_to_unshare = 0;
  ns->join_pidns = false;
  ns->join_ipcns = false;
  ns->must_fork = false;
  ns->delayed_userns_create = false;
  ns->userns_index = -1;
  ns->userns_index_origin = -1;
  ns->idx_pidns_to_join_immediately = -1;
  ns->idx_timens_to_join_immediately = -1;

- // 遍历config.json里的namespace。指定path是是要share的namespace，path=NULL是unshare的namespace
  for (i = 0; i < def->linux->namespaces_len; i++)
    {
      int value = libcrun_find_namespace (def->linux->namespaces[i]->type);
      ns->all_namespaces |= value;

      if (def->linux->namespaces[i]->path == NULL)
        ns->namespaces_to_unshare |= value;
      else
        {
          int fd;

          if (ns->fd_len >= MAX_NAMESPACES)
            return crun_make_error (err, 0, "too many namespaces to join");

          fd = open (def->linux->namespaces[i]->path, O_RDONLY | O_CLOEXEC);
-         // share USER的namespace要单独标注，后面有不同的处理逻辑
          if (value == CLONE_NEWUSER)
            {
+             ns->userns_index = ns->fd_len;
+             ns->userns_index_origin = i;
            }

          ns->fd[ns->fd_len] = fd;
          ns->index[ns->fd_len] = i;
          ns->value[ns->fd_len] = value;
          ns->fd_len++;
          ns->fd[ns->fd_len] = -1;
        }
    }

- // 如果host_uid!=0(非root)，NEWUSER namespace必须加上
  if (container->host_uid && (ns->all_namespaces & CLONE_NEWUSER) == 0)
    {
      libcrun_warning ("non root user need to have an 'user' namespace");
+     ns->all_namespaces |= CLONE_NEWUSER;
+     ns->namespaces_to_unshare |= CLONE_NEWUSER;
    }

  return 0;
}
```

- ***libcrun_run_linux_container -> init_container***
```diff
- init_container是属于container进程。
- 1. 先处理container进程的NEWPID和NEWTIME namespace，setns设置为目标namespace
- 2. fork一次。fork的父进程把new_pid传回给host端，然后退出
- 3. 在子进程里，setns需要share的namespace
```

```diff
static int
init_container (libcrun_container_t *container, int sync_socket_container, struct init_status_s *init_status,
                libcrun_error_t *err)
{
  runtime_spec_schema_config_schema *def = container->container_def;
  cleanup_close int mqueuefsfd = -1;
  cleanup_close int procfsfd = -1;
  pid_t pid_container = 0;
  size_t i;
  int ret;
  const char success = 0;

  if (init_status->idx_pidns_to_join_immediately >= 0 || init_status->idx_timens_to_join_immediately >= 0)
    {
      pid_t new_pid;

      if (init_status->idx_pidns_to_join_immediately >= 0)
        {
          ret = setns (init_status->fd[init_status->idx_pidns_to_join_immediately], CLONE_NEWPID);

          close_and_reset (&init_status->fd[init_status->idx_pidns_to_join_immediately]);
        }

      if (init_status->idx_timens_to_join_immediately >= 0)
        {
          ret = setns (init_status->fd[init_status->idx_timens_to_join_immediately], CLONE_NEWTIME);
          close_and_reset (&init_status->fd[init_status->idx_timens_to_join_immediately]);
        }

      new_pid = fork ();
      if (UNLIKELY (new_pid < 0))
        return crun_make_error (err, errno, "fork");

      if (new_pid)
        {
          /* Report the new PID to the parent and exit immediately.  */
          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &success, 1));
          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &new_pid, sizeof (new_pid)));
          _exit (0);
        }

      /* In the new processs.  Wait for the parent to receive the new PID.  */
      ret = expect_success_from_sync_socket (sync_socket_container, err);
    }

  ret = libcrun_set_oom (container, err);

  if (init_status->fd_len > 0)
    {
      ret = join_namespaces (def, init_status->fd, init_status->fd_len, init_status->index, true, err);
    }

  /* If the container needs to join an existing PID namespace, take a reference to it
     before creating a new user namespace, as we could lose the access to the existing
     namespace.  */
  if ((init_status->all_namespaces & CLONE_NEWUSER) && (init_status->join_pidns || init_status->join_ipcns))
    {
      for (i = 0; i < def->mounts_len; i++)
        {
          /* If for any reason the mount cannot be opened, ignore errors and continue.
             An error will be generated later if it is not possible to join the namespace.
          */
          if (init_status->join_pidns && strcmp (def->mounts[i]->type, "proc") == 0)
            procfsfd = fsopen_mount (def->mounts[i]);
          if (init_status->join_ipcns && strcmp (def->mounts[i]->type, "mqueue") == 0)
            mqueuefsfd = fsopen_mount (def->mounts[i]);
        }
    }

  if (init_status->all_namespaces & CLONE_NEWUSER)
    {
      if (init_status->delayed_userns_create)
        {
          ret = unshare (CLONE_NEWUSER);
          init_status->namespaces_to_unshare &= ~CLONE_NEWUSER;
          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &success, 1));
        }

      if (init_status->userns_index < 0)
        {
          char tmp;
          ret = TEMP_FAILURE_RETRY (read (sync_socket_container, &tmp, 1));
        }
      else
        {
          /* If we need to join another user namespace, do it immediately before creating any other namespace. */
          ret = setns (init_status->fd[init_status->userns_index], CLONE_NEWUSER);
        }

      ret = set_id_init (container, err);
    }

  ret = join_namespaces (def, init_status->fd, init_status->fd_len, init_status->index, false, err);

  if (init_status->namespaces_to_unshare & ~CLONE_NEWCGROUP)
    {
      /* New namespaces to create for the container.  */
      ret = unshare (init_status->namespaces_to_unshare & ~CLONE_NEWCGROUP);
    }

  if (init_status->all_namespaces & CLONE_NEWTIME)
    {
      const char *v = find_annotation (container, "run.oci.timens_offset");
      if (v)
        {
          ret = write_file ("/proc/self/timens_offsets", v, strlen (v), err);
        }
    }

- // 需要再fork一次
  if (init_status->must_fork)
    {
      /* A PID and a time namespace are joined when the new process is created.  */
      pid_container = fork ();

-    // 把grand child的PID发给host端，这才是最后的container_pid
      /* Report back the new PID.  */
      if (pid_container)
        {
          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &success, 1));

          ret = TEMP_FAILURE_RETRY (write (sync_socket_container, &pid_container, sizeof (pid_container)));
          _exit (EXIT_SUCCESS);
        }

      ret = expect_success_from_sync_socket (sync_socket_container, err);
    }

  ret = libcrun_container_setgroups (container, container->container_def->process, err);

  get_private_data (container)->procfsfd = get_and_reset (&procfsfd);
  get_private_data (container)->mqueuefsfd = get_and_reset (&mqueuefsfd);

  return 0;
}
```

> ***libcrun_run_linux_container -> libcrun_set_usernamespace***
```diff
- 生成uidmap和gidmap文件
```
```diff
int
libcrun_set_usernamespace (libcrun_container_t *container, pid_t pid, libcrun_error_t *err)
{
#define MAPPING_FMT_SIZE ("%" PRIu32 " %" PRIu32 " %" PRIu32 "\n")
#define MAPPING_FMT_1 ("%" PRIu32 " %" PRIu32 " 1\n")
  cleanup_free char *uid_map_file = NULL;
  cleanup_free char *gid_map_file = NULL;
  cleanup_free char *uid_map = NULL;
  cleanup_free char *gid_map = NULL;
  int uid_map_len, gid_map_len;
  int ret = 0;
  runtime_spec_schema_config_schema *def = container->container_def;

  if ((get_private_data (container)->unshare_flags & CLONE_NEWUSER) == 0)
    return 0;

  if (! def->linux->uid_mappings_len)
    {
      uid_map_len = format_default_id_mapping (&uid_map, container->container_uid, container->host_uid, 1);
      if (uid_map == NULL)
        {
          if (container->host_uid)
            uid_map_len = xasprintf (&uid_map, MAPPING_FMT_1, 0, container->host_uid);
          else
            uid_map_len = xasprintf (&uid_map, MAPPING_FMT_SIZE, 0, container->host_uid, container->container_uid + 1);
        }
    }
  else
    {
      size_t written = 0, s;
      char buffer[64];
      uid_map = xmalloc (sizeof (buffer) * def->linux->uid_mappings_len + 1);
      for (s = 0; s < def->linux->uid_mappings_len; s++)
        {
          size_t len;

          len = sprintf (buffer, MAPPING_FMT_SIZE, def->linux->uid_mappings[s]->container_id,
                         def->linux->uid_mappings[s]->host_id, def->linux->uid_mappings[s]->size);
          memcpy (uid_map + written, buffer, len);
          written += len;
        }
      uid_map[written] = '\0';
      uid_map_len = written;
    }

  if (! def->linux->gid_mappings_len)
    {
      gid_map_len = format_default_id_mapping (&gid_map, container->container_gid, container->host_uid, 0);
      if (gid_map == NULL)
        {
          if (container->host_gid)
            gid_map_len = xasprintf (&gid_map, MAPPING_FMT_1, container->container_gid, container->host_gid);
          else
            gid_map_len = xasprintf (&gid_map, MAPPING_FMT_SIZE, 0, container->host_gid, container->container_gid + 1);
        }
    }
  else
    {
      size_t written = 0, s;
      char buffer[64];
      gid_map = xmalloc (sizeof (buffer) * def->linux->gid_mappings_len + 1);
      for (s = 0; s < def->linux->gid_mappings_len; s++)
        {
          size_t len;

          len = sprintf (buffer, MAPPING_FMT_SIZE, def->linux->gid_mappings[s]->container_id,
                         def->linux->gid_mappings[s]->host_id, def->linux->gid_mappings[s]->size);
          memcpy (gid_map + written, buffer, len);
          written += len;
        }
      gid_map[written] = '\0';
      gid_map_len = written;
    }

  if (container->host_uid)
    ret = newgidmap (pid, gid_map, err);
  if (container->host_uid == 0 || ret < 0)
    {
      if (ret < 0)
        {
          if (! def->linux->uid_mappings_len)
            libcrun_warning ("unable to invoke newgidmap, will try creating a user namespace with single mapping as an alternative");
          crun_error_release (err);
        }

      xasprintf (&gid_map_file, "/proc/%d/gid_map", pid);
+     ret = write_file (gid_map_file, gid_map, gid_map_len, err);
      if (ret < 0 && ! def->linux->gid_mappings_len)
        {
          size_t single_mapping_len;
          char single_mapping[32];
          crun_error_release (err);

          ret = deny_setgroups (container, pid, err);

          single_mapping_len = sprintf (single_mapping, MAPPING_FMT_1, container->container_gid, container->host_gid);
+         ret = write_file (gid_map_file, single_mapping, single_mapping_len, err);
        }
    }
  if (UNLIKELY (ret < 0))
    return ret;

  if (container->host_uid)
    ret = newuidmap (pid, uid_map, err);
  if (container->host_uid == 0 || ret < 0)
    {
      xasprintf (&uid_map_file, "/proc/%d/uid_map", pid);
      ret = write_file (uid_map_file, uid_map, uid_map_len, err);
      if (ret < 0 && ! def->linux->uid_mappings_len)
        {
          size_t single_mapping_len;
          char single_mapping[32];
          crun_error_release (err);

          if (! get_private_data (container)->deny_setgroups)
            {
              ret = deny_setgroups (container, pid, err);
            }

          single_mapping_len = sprintf (single_mapping, MAPPING_FMT_1, container->container_uid, container->host_uid);
+         ret = write_file (uid_map_file, single_mapping, single_mapping_len, err);
        }
    }
  return 0;

#undef MAPPING_FMT_SIZE
#undef MAPPING_FMT_1
}
```
> libcrun_run_linux_container -> init_container -> join_namespaces
```diff
static int
join_namespaces (runtime_spec_schema_config_schema *def, int *namespaces_to_join, int n_namespaces_to_join,
                 int *namespaces_to_join_index, bool ignore_join_errors, libcrun_error_t *err)
{
  int ret;
  int i;

  for (i = 0; i < n_namespaces_to_join; i++)
    {
      cleanup_free char *cwd = NULL;
      int orig_index = namespaces_to_join_index[i];
      int value;

      if (namespaces_to_join[i] < 0)
        continue;

-     // 忽略NEWUSER
      /* Skip the user namespace.  */
      value = libcrun_find_namespace (def->linux->namespaces[orig_index]->type);
      if (value == CLONE_NEWUSER)
        continue;

      if (value == CLONE_NEWNS)
        {
          cwd = getcwd (NULL, 0);
        }

      ret = setns (namespaces_to_join[i], value);
      close_and_reset (&namespaces_to_join[i]);

      if (value == CLONE_NEWNS)
        {
          ret = chdir (cwd);
        }
    }
  return 0;
}
```

- ***libcrun_container_run_internal -> wait_for_process***
```diff
static int
wait_for_process (pid_t pid, libcrun_context_t *context, int terminal_fd, int notify_socket, int container_ready_fd,
                  int seccomp_notify_fd, const char *seccomp_notify_plugins, libcrun_error_t *err)
{
  cleanup_close int epollfd = -1;
  cleanup_close int signalfd = -1;
  int ret, container_exit_code = 0, last_process;
  sigset_t mask;
  int fds[10];
  int levelfds[10];
  int levelfds_len = 0;
  int fds_len = 0;
  cleanup_seccomp_notify_context struct seccomp_notify_context_s *seccomp_notify_ctx = NULL;

  container_exit_code = 0;

  if (context->pid_file)
    {
      char buf[12];
      size_t buf_len = sprintf (buf, "%d", pid);
      ret = write_file_with_flags (context->pid_file, O_CREAT | O_TRUNC, buf, buf_len, err);
    }

  /* Also exit if there is nothing more to wait for.  */
  if (context->detach && notify_socket < 0)
    return 0;

  if (container_ready_fd >= 0)
    {
      ret = 0;
      TEMP_FAILURE_RETRY (write (container_ready_fd, &ret, sizeof (ret)));
      close_and_reset (&container_ready_fd);
    }

  sigfillset (&mask);
  ret = sigprocmask (SIG_BLOCK, &mask, NULL);

  signalfd = create_signalfd (&mask, err);

  ret = reap_subprocesses (pid, &container_exit_code, &last_process, err);
  if (last_process)
    return container_exit_code;

  if (seccomp_notify_fd >= 0)
    {
      cleanup_free char *state_root = NULL;
      cleanup_free char *oci_config_path = NULL;

      struct libcrun_load_seccomp_notify_conf_s conf;
      memset (&conf, 0, sizeof conf);

      state_root = libcrun_get_state_directory (context->state_root, context->id);

      ret = append_paths (&oci_config_path, err, state_root, "config.json", NULL);

      conf.runtime_root_path = state_root;
      conf.name = context->id;
      conf.bundle_path = context->bundle;
      conf.oci_config_path = oci_config_path;

      ret = set_blocking_fd (seccomp_notify_fd, 0, err);

      ret = libcrun_load_seccomp_notify_plugins (&seccomp_notify_ctx, seccomp_notify_plugins, &conf, err);

      fds[fds_len++] = seccomp_notify_fd;
    }

  fds[fds_len++] = signalfd;
  if (notify_socket >= 0)
    fds[fds_len++] = notify_socket;
  if (terminal_fd >= 0)
    {
      fds[fds_len++] = 0;
      levelfds[levelfds_len++] = terminal_fd;
    }
  fds[fds_len++] = -1;
  levelfds[levelfds_len++] = -1;

  epollfd = epoll_helper (fds, levelfds, err);

  while (1)
    {
      struct signalfd_siginfo si;
      ssize_t res;
      struct epoll_event events[10];
      int i, nr_events;

      nr_events = TEMP_FAILURE_RETRY (epoll_wait (epollfd, events, 10, -1));

      for (i = 0; i < nr_events; i++)
        {
          if (events[i].data.fd == 0)
            {
              ret = copy_from_fd_to_fd (0, terminal_fd, 0, err);
            }
          else if (events[i].data.fd == seccomp_notify_fd)
            {
              ret = libcrun_seccomp_notify_plugins (seccomp_notify_ctx, seccomp_notify_fd, err);
            }
          else if (events[i].data.fd == terminal_fd)
            {
              ret = set_blocking_fd (terminal_fd, 0, err);
              ret = copy_from_fd_to_fd (terminal_fd, 1, 1, err);

              ret = set_blocking_fd (terminal_fd, 1, err);
            }
          else if (events[i].data.fd == notify_socket)
            {
              ret = handle_notify_socket (notify_socket, err);
              if (ret && context->detach)
                return 0;
            }
          else if (events[i].data.fd == signalfd)
            {
              res = TEMP_FAILURE_RETRY (read (signalfd, &si, sizeof (si)));
              if (si.ssi_signo == SIGCHLD)
                {
                  ret = reap_subprocesses (pid, &container_exit_code, &last_process, err);
                  if (last_process)
                    return container_exit_code;
                }
              else
                {
                  /* Send any other signal to the child process.  */
                  ret = kill (pid, si.ssi_signo);
                }
            }
          else
            {
              return crun_make_error (err, 0, "unknown fd from epoll_wait");
            }
        }
    }

  return 0;
}
```

- ***container_init***
```diff
- container_init是容器的entrypoint，也是执行的最后一步
```
```diff
/* Entrypoint to the container.  */
static int
container_init (void *args, char *notify_socket, int sync_socket, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  int ret;
  runtime_spec_schema_config_schema *def = entrypoint_args->container->container_def;
  cleanup_free const char *exec_path = NULL;
  __attribute__ ((unused)) cleanup_free char *notify_socket_cleanup = notify_socket;
  pid_t own_pid = 0;

  entrypoint_args->sync_socket = sync_socket;

  crun_set_output_handler (log_write_to_sync_socket, args, false);

  /* sync receive own pid.  */
  ret = TEMP_FAILURE_RETRY (read (sync_socket, &own_pid, sizeof (own_pid)));
  if (UNLIKELY (ret != sizeof (own_pid)))
    {
      if (ret >= 0)
        errno = 0;
      return crun_make_error (err, errno, "read from sync socket");
    }

- // 完成contaienr最后阶段初始化工作，如HOME，mounts, console, hostname，capabilities, 
+ ret = container_init_setup (args, own_pid, notify_socket, sync_socket, &exec_path, err);

  entrypoint_args->sync_socket = -1;

  ret = unblock_signals (err);

  /* sync 4.  */
  ret = sync_socket_send_sync (sync_socket, false, err);

  close_and_reset (&sync_socket);

- // 在fifo_exec_wait_fd阻塞等待，直到crun start解除阻塞
  if (entrypoint_args->context->fifo_exec_wait_fd >= 0)
    {
      char buffer[1];
      fd_set read_set;
      cleanup_close int fd = entrypoint_args->context->fifo_exec_wait_fd;
      entrypoint_args->context->fifo_exec_wait_fd = -1;

      FD_ZERO (&read_set);
      FD_SET (fd, &read_set);
      do
        {
          ret = select (fd + 1, &read_set, NULL, NULL, NULL);

+         ret = TEMP_FAILURE_RETRY (read (fd, buffer, sizeof (buffer)));
      } while (ret == 0);

      close_and_reset (&entrypoint_args->context->fifo_exec_wait_fd);
    }

  crun_set_output_handler (log_write_to_stderr, NULL, false);

  if (def->process && def->process->no_new_privileges)
    {
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      cleanup_free char *seccomp_fd_payload = NULL;
      size_t seccomp_fd_payload_len = 0;

      if (def->linux && def->linux->seccomp)
        {
          seccomp_flags = def->linux->seccomp->flags;
          seccomp_flags_len = def->linux->seccomp->flags_len;
        }

      if (entrypoint_args->seccomp_receiver_fd >= 0)
        {
          ret = get_seccomp_receiver_fd_payload (entrypoint_args->container, "creating", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
        }

      ret = libcrun_apply_seccomp (entrypoint_args->seccomp_fd, entrypoint_args->seccomp_receiver_fd,
                                   seccomp_fd_payload, seccomp_fd_payload_len, seccomp_flags,
                                   seccomp_flags_len, err);
      close_and_reset (&entrypoint_args->seccomp_fd);
      close_and_reset (&entrypoint_args->seccomp_receiver_fd);
    }

  if (def->hooks && def->hooks->start_container_len)
    {
      libcrun_container_t *container = entrypoint_args->container;

      ret = do_hooks (def, 0, container->context->id, false, NULL, "starting", (hook **) def->hooks->start_container,
                      def->hooks->start_container_len, entrypoint_args->hooks_out_fd, entrypoint_args->hooks_err_fd,
                      err);

      /* Seek stdout/stderr to the end.  If the hooks were using the same files,
         the container process overwrites what was previously written.  */
      (void) lseek (1, 0, SEEK_END);
      (void) lseek (2, 0, SEEK_END);
    }

- // 如果定义了其它exec执行方式，就用该方式执行entrypoint
+ if (entrypoint_args->exec_func)
    {
      ret = entrypoint_args->exec_func (entrypoint_args->container, entrypoint_args->exec_func_arg, exec_path,
                                        def->process->args);
      _exit (ret);
    }

- // 默认用execv来执行entrypoint
+ TEMP_FAILURE_RETRY (execv (exec_path, def->process->args));

  if (errno == ENOENT)
    return crun_make_error (err, errno, "exec container process (missing dynamic library?) `%s`", exec_path);

  return crun_make_error (err, errno, "exec container process `%s`", exec_path);
}
```

> ***container_init -> container_init_setup***
```diff
/* Initialize the environment where the container process runs.
   It is used by the container init process.  */
static int
container_init_setup (void *args, pid_t own_pid, char *notify_socket, int sync_socket, const char **exec_path, libcrun_error_t *err)
{
  struct container_entrypoint_s *entrypoint_args = args;
  libcrun_container_t *container = entrypoint_args->container;
  int ret;
  int has_terminal;
  cleanup_close int console_socket = -1;
  cleanup_close int console_socketpair = -1;
  runtime_spec_schema_config_schema *def = container->container_def;
  runtime_spec_schema_config_schema_process_capabilities *capabilities;
  cleanup_free char *rootfs = NULL;
  int no_new_privs;

  ret = libcrun_configure_handler (args, err);

  ret = initialize_security (def->process, err);

  ret = libcrun_configure_network (container, err);

  if (def->root && def->root->path)
    {
      rootfs = realpath (def->root->path, NULL);
      if (UNLIKELY (rootfs == NULL))
        {
          /* If realpath failed for any reason, try the relative directory.  */
          rootfs = xstrdup (def->root->path);
        }
    }

  if (entrypoint_args->terminal_socketpair[0] >= 0)
    {
      close_and_reset (&entrypoint_args->terminal_socketpair[0]);
      console_socketpair = entrypoint_args->terminal_socketpair[1];
    }

  /* sync 1.  */
  ret = sync_socket_wait_sync (NULL, sync_socket, false, err);

  has_terminal = container->container_def->process && container->container_def->process->terminal;
  if (has_terminal && entrypoint_args->context->console_socket)
    console_socket = entrypoint_args->console_socket_fd;

  ret = libcrun_set_sysctl (container, err);

  /* sync 2 and 3 are sent as part of libcrun_set_mounts.  */
+ ret = libcrun_set_mounts (container, rootfs, send_sync_cb, &sync_socket, err);

#if HAVE_DLOPEN && HAVE_LIBKRUN
  /* explicitly configure kvm device if binary is invoked as krun */
  if (entrypoint_args->context->handler != NULL && (strcmp (entrypoint_args->context->handler, "krun") == 0))
    {
      ret = libcrun_create_kvm_device (container, err);
 
    }
#endif

  if (def->hooks && def->hooks->create_container_len)
    {
      ret = do_hooks (def, 0, container->context->id, false, NULL, "created", (hook **) def->hooks->create_container,
                      def->hooks->create_container_len, entrypoint_args->hooks_out_fd, entrypoint_args->hooks_err_fd,
                      err);
    }

  if (def->process)
    {
      ret = libcrun_set_selinux_exec_label (def->process, err);
      ret = libcrun_set_apparmor_profile (def->process, err);

    }

  ret = mark_for_close_fds_ge_than (entrypoint_args->context->preserve_fds + 3, err);

- // 使用pivot_root命令切换根目录到rootfs
  if (rootfs)
    {
      ret = libcrun_do_pivot_root (container, entrypoint_args->context->no_pivot, rootfs, err);
    }

  ret = libcrun_reopen_dev_null (err);

  if (clearenv ())
    return crun_make_error (err, errno, "clearenv");

  if (def->process)
    {
      size_t i;

      for (i = 0; i < def->process->env_len; i++)
        if (putenv (def->process->env[i]) < 0)
          return crun_make_error (err, errno, "putenv `%s`", def->process->env[i]);
    }

  if (getenv ("HOME") == NULL)
    {
      ret = set_home_env (container->container_uid);
      if (UNLIKELY (ret < 0 && errno != ENOTSUP))
        {
          setenv ("HOME", "/", 1);
          libcrun_warning ("cannot detect HOME environment variable, setting default");
        }
    }

  if (def->process && def->process->cwd)
    if (UNLIKELY (chdir (def->process->cwd) < 0))
      return crun_make_error (err, errno, "chdir");

  if (def->process && def->process->args)
    {
      *exec_path = find_executable (def->process->args[0], def->process->cwd);
    }

-  // 脱离父进程包括它的终端控制。
+  ret = setsid ();
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "setsid");

  if (has_terminal)
    {
      cleanup_close int terminal_fd = -1;

      fflush (stderr);

-     // 得到pty伪终端的masterfd，从设备在/dev/pts/xx
+     terminal_fd = libcrun_set_terminal (container, err);

-     // 把伪终端masterfd通过console_socket传给host端
      if (console_socket >= 0)
        {
          ret = send_fd_to_socket (console_socket, terminal_fd, err);
          close_and_reset (&console_socket);
        }
      else if (entrypoint_args->has_terminal_socket_pair && console_socketpair >= 0)
        {
          ret = send_fd_to_socket (console_socketpair, terminal_fd, err);
          close_and_reset (&console_socketpair);
        }
    }

- // 设置hostname
+ ret = libcrun_set_hostname (container, err);

  if (container->container_def->linux && container->container_def->linux->personality)
    {
      ret = libcrun_set_personality (container->container_def->linux->personality, err);
    }

  if (def->process && def->process->user)
    umask (def->process->user->umask_present ? def->process->user->umask : 0022);

  if (def->process && ! def->process->no_new_privileges)
    {
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      cleanup_free char *seccomp_fd_payload = NULL;
      size_t seccomp_fd_payload_len = 0;

      if (def->linux && def->linux->seccomp)
        {
          seccomp_flags = def->linux->seccomp->flags;
          seccomp_flags_len = def->linux->seccomp->flags_len;
        }

      if (entrypoint_args->seccomp_receiver_fd >= 0)
        {
          ret = get_seccomp_receiver_fd_payload (container, "creating", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
        }

      ret = libcrun_apply_seccomp (entrypoint_args->seccomp_fd, entrypoint_args->seccomp_receiver_fd,
                                   seccomp_fd_payload, seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);

      close_and_reset (&entrypoint_args->seccomp_fd);
      close_and_reset (&entrypoint_args->seccomp_receiver_fd);
    }

  if (entrypoint_args->container->use_intermediate_userns)
    {
      ret = libcrun_create_final_userns (entrypoint_args->container, err);
    }
    
- // 设置capabilities
  capabilities = def->process ? def->process->capabilities : NULL;
  no_new_privs = def->process ? def->process->no_new_privileges : 1;
+ ret = libcrun_set_caps (capabilities, container->container_uid, container->container_gid, no_new_privs, err);

  if (notify_socket)
    {
      if (putenv (notify_socket) < 0)
        return crun_make_error (err, errno, "putenv `%s`", notify_socket);
    }

  return 0;
}
```

>> ***container_init -> container_init_setup -> libcrun_set_mounts***
```diff
int
libcrun_set_mounts (libcrun_container_t *container, const char *rootfs, set_mounts_cb_t cb, void *cb_data, libcrun_error_t *err)
{
  int rootfsfd = -1;
  int ret = 0, is_user_ns = 0;
  unsigned long rootfs_propagation = 0;
  cleanup_close int rootfsfd_cleanup = -1;
  runtime_spec_schema_config_schema *def = container->container_def;

  if (rootfs == NULL || def->mounts == NULL)
    return 0;

  if (def->linux->rootfs_propagation)
    rootfs_propagation = get_mount_flags (def->linux->rootfs_propagation, 0, NULL, NULL);

  if ((rootfs_propagation & (MS_SHARED | MS_SLAVE | MS_PRIVATE | MS_UNBINDABLE)) == 0)
    rootfs_propagation = MS_REC | MS_PRIVATE;

  get_private_data (container)->rootfs_propagation = rootfs_propagation;

  if (get_private_data (container)->unshare_flags & CLONE_NEWNS)
    {
      ret = do_mount (container, NULL, -1, "/", NULL, rootfs_propagation, NULL, LABEL_MOUNT, err);
      ret = make_parent_mount_private (rootfs, err);
      ret = do_mount (container, rootfs, -1, rootfs, NULL, MS_BIND | MS_REC | MS_PRIVATE, NULL, LABEL_MOUNT, err);
    }

  if (rootfs == NULL)
    rootfsfd = AT_FDCWD;
  else
    {
      rootfsfd = rootfsfd_cleanup = open (rootfs, O_PATH | O_CLOEXEC);
    }

  get_private_data (container)->rootfs = rootfs;
  get_private_data (container)->rootfsfd = rootfsfd;
  get_private_data (container)->rootfs_len = rootfs ? strlen (rootfs) : 0;

  if (def->root->readonly)
    {
      struct remount_s *r;
      unsigned long remount_flags = MS_REMOUNT | MS_BIND | MS_RDONLY;
      int fd;

      fd = dup (rootfsfd);
      if (UNLIKELY (fd < 0))
        return crun_make_error (err, errno, "dup fd for `%s`", rootfs);

      r = make_remount (fd, rootfs, remount_flags, NULL, get_private_data (container)->remounts);
      get_private_data (container)->remounts = r;
    }

  ret = libcrun_container_enter_cgroup_ns (container, err);
  ret = do_mounts (container, rootfsfd, rootfs, err);

  is_user_ns = (get_private_data (container)->unshare_flags & CLONE_NEWUSER);
  if (! is_user_ns)
    {
      is_user_ns = check_running_in_user_namespace (err);
    }

  if (! get_private_data (container)->mount_dev_from_host)
    {
      ret = create_missing_devs (container, is_user_ns ? true : false, err);
    }

  /* Notify the callback after all the mounts are ready but before making them read-only.  */
  if (cb)
    {
      ret = cb (cb_data, err);
    }

  ret = do_finalize_notify_socket (container, err);

  ret = do_masked_and_readonly_paths (container, err);

  ret = finalize_mounts (container, err);

  get_private_data (container)->rootfsfd = -1;

  return 0;
}
```
