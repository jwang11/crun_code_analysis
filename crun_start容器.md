#crun start容器
> 主程序部分请参考<crun_create容器.md>

### Start子命令
```diff
- $ crun start --help
Usage: start [OPTION...] start CONTAINER
OCI runtime

  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

- start子命令程序入口
```diff
int
crun_command_start (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg = 0, ret;

  libcrun_context_t crun_context = {
    0,
  };

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, NULL);
  crun_assert_n_args (argc - first_arg, 1, 1);

  ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

- return libcrun_container_start (&crun_context, argv[first_arg], err);
}
```
- start开始之前，一般是运行过crun_create，状态是
```diff
- $ ls /run/crun/busybox1/
config.json  exec.fifo  status

+ config.json是spec的一份copy
+ exec.fifo 是为了阻塞
+ status 文件是状态文件
{
    "pid": 139179,
    "process-start-time": 263473330,
    "cgroup-path": "/busybox1",
    "scope": "",
    "rootfs": "rootfs",
    "systemd-cgroup": false,
    "bundle": "/home/jwang/my_container",
    "created": "2021-08-29T14:34:52.000293421Z",
    "owner": "root",
    "detached": true,
    "external_descriptors": "[\"/dev/pts/1\",\"/dev/pts/1\",\"/dev/pts/1\"]"
}
```
- crun_command_start -> libcrun_container_start
```diff
int
libcrun_container_start (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container = NULL;
  const char *state_root = context->state_root;
  runtime_spec_schema_config_schema *def;
  libcrun_container_status_t status = {};
  cleanup_close int fd = -1;
  int ret;

+ ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

- // 检查contaienr的PID是否在
+ ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! ret)
    return crun_make_error (err, 0, "container `%s` is not running", id);

+ ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (context->notify_socket)
    {
      ret = get_notify_fd (context, container, &fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

+ ret = libcrun_status_write_exec_fifo (context->state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  def = container->container_def;

  if (context->notify_socket)
    {
      if (fd >= 0)
        {
          fd_set read_set;

          while (1)
            {
              struct timeval timeout = {
                .tv_sec = 0,
                .tv_usec = 10000,
              };
              FD_ZERO (&read_set);
              FD_SET (fd, &read_set);

              ret = select (fd + 1, &read_set, NULL, NULL, &timeout);
              if (UNLIKELY (ret < 0))
                return ret;
              if (ret)
                {
                  ret = handle_notify_socket (fd, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (ret)
                    break;
                }
              else
                {
                  ret = libcrun_is_container_running (&status, err);
                  if (UNLIKELY (ret < 0))
                    return ret;
                  if (! ret)
                    return 0;
                }
            }
        }
    }

  /* The container is considered running only after we got the notification from the
     notify_socket, if any.  */
  if (def->hooks && def->hooks->poststart_len)
    {
      cleanup_close int hooks_out_fd = -1;
      cleanup_close int hooks_err_fd = -1;

      ret = open_hooks_output (container, &hooks_out_fd, &hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = do_hooks (def, status.pid, context->id, true, status.bundle, "running", (hook **) def->hooks->poststart,
                      def->hooks->poststart_len, hooks_out_fd, hooks_err_fd, err);
      if (UNLIKELY (ret < 0))
        crun_error_release (err);
    }

  return 0;
}
```
> libcrun_read_container_status
```diff
int
libcrun_read_container_status (libcrun_container_status_t *status, const char *state_root, const char *id,
                               libcrun_error_t *err)
{
  cleanup_free char *buffer = NULL;
  char err_buffer[256];
  int ret;
  cleanup_free char *file = get_state_directory_status_file (state_root, id);
  yajl_val tree, tmp;

  ret = read_all_file (file, &buffer, NULL, err);
  if (UNLIKELY (ret < 0))
    return ret;

  tree = yajl_tree_parse (buffer, err_buffer, sizeof (err_buffer));
  if (UNLIKELY (tree == NULL))
    return crun_make_error (err, 0, "cannot parse status file: %s", err_buffer);

  {
    const char *pid_path[] = { "pid", NULL };
    tmp = yajl_tree_get (tree, pid_path, yajl_t_number);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'pid' missing in %s", file);
    status->pid = strtoull (YAJL_GET_NUMBER (tmp), NULL, 10);
  }
  {
    const char *process_start_time_path[] = { "process-start-time", NULL };
    tmp = yajl_tree_get (tree, process_start_time_path, yajl_t_number);
    if (UNLIKELY (tmp == NULL))
      status->process_start_time = 0; /* backwards compatibility */
    else
      status->process_start_time = strtoull (YAJL_GET_NUMBER (tmp), NULL, 10);
  }
  {
    const char *cgroup_path[] = { "cgroup-path", NULL };
    tmp = yajl_tree_get (tree, cgroup_path, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'cgroup-path' missing in %s", file);
    status->cgroup_path = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *scope[] = { "scope", NULL };
    tmp = yajl_tree_get (tree, scope, yajl_t_string);
    status->scope = tmp ? xstrdup (YAJL_GET_STRING (tmp)) : NULL;
  }
  {
    const char *rootfs[] = { "rootfs", NULL };
    tmp = yajl_tree_get (tree, rootfs, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'rootfs' missing in %s", file);
    status->rootfs = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *systemd_cgroup[] = { "systemd-cgroup", NULL };
    status->systemd_cgroup = YAJL_IS_TRUE (yajl_tree_get (tree, systemd_cgroup, yajl_t_true));
  }
  {
    const char *bundle[] = { "bundle", NULL };
    tmp = yajl_tree_get (tree, bundle, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'bundle' missing in %s", file);
    status->bundle = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *created[] = { "created", NULL };
    tmp = yajl_tree_get (tree, created, yajl_t_string);
    if (UNLIKELY (tmp == NULL))
      return crun_make_error (err, 0, "'created' missing in %s", file);
    status->created = xstrdup (YAJL_GET_STRING (tmp));
  }
  {
    const char *owner[] = { "owner", NULL };
    tmp = yajl_tree_get (tree, owner, yajl_t_string);
    status->owner = tmp ? xstrdup (YAJL_GET_STRING (tmp)) : NULL;
  }
  {
    const char *detached[] = { "detached", NULL };
    status->detached = YAJL_IS_TRUE (yajl_tree_get (tree, detached, yajl_t_true));
  }
  {
    const char *external[] = { "external_descriptors", NULL };
    const unsigned char *buf = NULL;
    yajl_gen gen = NULL;
    size_t buf_len;

    gen = yajl_gen_alloc (NULL);
    if (gen == NULL)
      return crun_make_error (err, errno, "yajl_gen_alloc");
    yajl_gen_array_open (gen);

    tmp = yajl_tree_get (tree, external, yajl_t_array);
    if (tmp && YAJL_IS_ARRAY (tmp))
      {
        size_t len = tmp->u.array.len;
        size_t i;
        for (i = 0; i < len; ++i)
          {
            yajl_val s = tmp->u.array.values[i];
            if (s && YAJL_IS_STRING (s))
              {
                char *str = YAJL_GET_STRING (s);
                yajl_gen_string (gen, YAJL_STR (str), strlen (str));
              }
          }
      }
    yajl_gen_array_close (gen);
    yajl_gen_get_buf (gen, &buf, &buf_len);
    if (buf)
      status->external_descriptors = xstrdup ((const char *) buf);
    yajl_gen_free (gen);
  }
  yajl_tree_free (tree);
  return 0;
}
```
> libcrun_is_container_running
```diff
int
libcrun_is_container_running (libcrun_container_status_t *status, libcrun_error_t *err)
{
  int ret;
- // kill -0的说明，如果参数是0，不会发送任何的信号，但是仍会执行错误检查，可以用来检测某个进程ID或进程组ID是否存在
+ ret = kill (status->pid, 0);
  if (UNLIKELY (ret < 0) && errno != ESRCH)
    return crun_make_error (err, errno, "kill");

  if (ret == 0)
    return libcrun_check_pid_valid (status, err);

  return 0; /* stopped */
}
```
> read_container_config_from_state
```
static int
read_container_config_from_state (libcrun_container_t **container, const char *state_root, const char *id,
                                  libcrun_error_t *err)
{
  cleanup_free char *config_file = NULL;
  cleanup_free char *dir = NULL;
  int ret;

  *container = NULL;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory from `%s`", state_root);

  ret = append_paths (&config_file, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  *container = libcrun_container_load_from_file (config_file, err);
  if (*container == NULL)
    return crun_make_error (err, 0, "error loading `%s`", config_file);

  return 0;
}
```

> libcrun_status_write_exec_fifo
```
int
libcrun_status_write_exec_fifo (const char *state_root, const char *id, libcrun_error_t *err)
{
  cleanup_free char *state_dir = libcrun_get_state_directory (state_root, id);
  cleanup_free char *fifo_path = NULL;
  char buffer[1] = {
    0,
  };
  cleanup_close int fd = -1;
  int ret;

  ret = append_paths (&fifo_path, err, state_dir, "exec.fifo", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  fd = open (fifo_path, O_WRONLY);
  if (UNLIKELY (fd < 0))
    return crun_make_error (err, errno, "cannot open `%s`", fifo_path);

  ret = unlink (fifo_path);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "unlink `%s`", fifo_path);

-  // crun create的时候阻塞在read(fifo...)，现在解除阻塞继续执行entrypoint里定义的命令
+  ret = TEMP_FAILURE_RETRY (write (fd, buffer, 1));
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "read from exec.fifo");

  return strtoll (buffer, NULL, 10);
}
```
