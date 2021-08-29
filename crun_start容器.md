#crun start容器
> 主程序部分请参考<crun_create容器.md>

### Start子命令
```diff
- crun start --help
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

- crun_command_start -> libcrun_container_start
```
int
libcrun_container_start (libcrun_context_t *context, const char *id, libcrun_error_t *err)
{
  cleanup_container libcrun_container_t *container = NULL;
  const char *state_root = context->state_root;
  runtime_spec_schema_config_schema *def;
  libcrun_container_status_t status = {};
  cleanup_close int fd = -1;
  int ret;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (! ret)
    return crun_make_error (err, 0, "container `%s` is not running", id);

  ret = read_container_config_from_state (&container, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (context->notify_socket)
    {
      ret = get_notify_fd (context, container, &fd, err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  ret = libcrun_status_write_exec_fifo (context->state_root, id, err);
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
