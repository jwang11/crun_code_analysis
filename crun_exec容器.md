# crun_exec容器
> 主程序部分请参考(crun_create容器.md)

### Exec子命令
```diff
- $ crun exec --help
Usage: exec [OPTION...] exec CONTAINER cmd
OCI runtime

      --apparmor=VALUE       set the apparmor profile for the process
      --console-socket=SOCKET   path to a socket that will receive the ptmx end
                             of the tty
      --cwd=CWD              current working directory
  -c, --cap=CAP              add a capability
  -d, --detach               detach the command in the background
  -e, --env=ENV              add an environment variable
      --no-new-privs         set the no new privileges value for the process
  -p, --process=FILE         path to the process.json
      --pid-file=FILE        where to write the PID of the container
      --preserve-fds=N       pass additional FDs to the container
      --process-label=VALUE  set the asm process label for the process commonly
                             used with selinux
  -t, --tty[=TTY]            allocate a pseudo-TTY
  -u, --user=USERSPEC        specify the user in the form UID[:GID]
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version
```

- Exec子命令程序入口
```diff
int
crun_command_exec (struct crun_global_arguments *global_args, int argc, char **argv, libcrun_error_t *err)
{
  int first_arg = 0, ret = 0;
  libcrun_context_t crun_context = {
    0,
  };

  crun_context.preserve_fds = 0;

  argp_parse (&run_argp, argc, argv, ARGP_IN_ORDER, &first_arg, &exec_options);
  crun_assert_n_args (argc - first_arg, exec_options.process ? 1 : 2, -1);

+ ret = init_libcrun_context (&crun_context, argv[first_arg], global_args, err);
  if (UNLIKELY (ret < 0))
    return ret;

  crun_context.detach = exec_options.detach;
  crun_context.console_socket = exec_options.console_socket;
  crun_context.pid_file = exec_options.pid_file;
  crun_context.preserve_fds = exec_options.preserve_fds;

  if (getenv ("LISTEN_FDS"))
    crun_context.preserve_fds += strtoll (getenv ("LISTEN_FDS"), NULL, 10);

- // 判断执行指令是从外部process.json传入，还是命令行传入
  if (exec_options.process)
+   return libcrun_container_exec_process_file (&crun_context, argv[first_arg], exec_options.process, err);
  else
    {
      runtime_spec_schema_config_schema_process *process = xmalloc0 (sizeof (*process));
      int i;

      process->args_len = argc;
      process->args = xmalloc0 ((argc + 1) * sizeof (*process->args));
      for (i = 0; i < argc - first_arg; i++)
        process->args[i] = xstrdup (argv[first_arg + i + 1]);
      process->args[i] = NULL;
      if (exec_options.cwd)
        process->cwd = exec_options.cwd;
      process->terminal = exec_options.tty;
      process->env = exec_options.env;
      process->env_len = exec_options.env_size;
      process->user = make_oci_process_user (exec_options.user);

      if (exec_options.process_label != NULL)
        process->selinux_label = exec_options.process_label;

      if (exec_options.apparmor != NULL)
        process->apparmor_profile = exec_options.apparmor;

      if (exec_options.cap_size > 0)
        {
          runtime_spec_schema_config_schema_process_capabilities *capabilities
              = xmalloc (sizeof (runtime_spec_schema_config_schema_process_capabilities));

          capabilities->effective = exec_options.cap;
          capabilities->effective_len = exec_options.cap_size;

          capabilities->inheritable = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->inheritable_len = exec_options.cap_size;

          capabilities->bounding = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->bounding_len = exec_options.cap_size;

          capabilities->ambient = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->ambient_len = exec_options.cap_size;

          capabilities->permitted = dup_array (exec_options.cap, exec_options.cap_size);
          capabilities->permitted_len = exec_options.cap_size;

          process->capabilities = capabilities;
        }

      // noNewPriviledges will remain `false` if basespec has `false` unless specified
      // Default is always `true` in generated basespec config
      if (exec_options.no_new_privs)
        process->no_new_privileges = 1;
+     ret = libcrun_container_exec (&crun_context, argv[first_arg], process, err);
      free_runtime_spec_schema_config_schema_process (process);
      return ret;
    }
}
```

- crun_command_exec -> libcrun_container_exec
```diff
int
libcrun_container_exec (libcrun_context_t *context, const char *id, runtime_spec_schema_config_schema_process *process,
                        libcrun_error_t *err)
{
  int container_status, ret;
  pid_t pid;
  libcrun_container_status_t status = {};
  const char *state_root = context->state_root;
  cleanup_close int terminal_fd = -1;
  cleanup_close int seccomp_fd = -1;
  cleanup_terminal void *orig_terminal = NULL;
  cleanup_free char *config_file = NULL;
  cleanup_container libcrun_container_t *container = NULL;
  cleanup_free char *dir = NULL;
  cleanup_free const char *exec_path = NULL;
  int container_ret_status[2];
  cleanup_close int pipefd0 = -1;
  cleanup_close int pipefd1 = -1;
  cleanup_close int seccomp_receiver_fd = -1;
  cleanup_close int own_seccomp_receiver_fd = -1;
  cleanup_close int seccomp_notify_fd = -1;
  const char *seccomp_notify_plugins = NULL;
  char b;

  ret = libcrun_read_container_status (&status, state_root, id, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = libcrun_is_container_running (&status, err);
  if (UNLIKELY (ret < 0))
    return ret;
  container_status = ret;

  dir = libcrun_get_state_directory (state_root, id);
  if (UNLIKELY (dir == NULL))
    return crun_make_error (err, 0, "cannot get state directory");

  ret = append_paths (&config_file, err, dir, "config.json", NULL);
  if (UNLIKELY (ret < 0))
    return ret;

  container = libcrun_container_load_from_file (config_file, err);
  if (container == NULL)
    return crun_make_error (err, 0, "error loading config.json");

  if (container_status == 0)
    return crun_make_error (err, 0, "the container `%s` is not running.", id);

  ret = block_signals (err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = open_seccomp_output (context->id, &seccomp_fd, true, context->state_root, err);
  if (UNLIKELY (ret < 0))
    return ret;

  if (seccomp_fd >= 0)
    {
      ret = get_seccomp_receiver_fd (container, &seccomp_receiver_fd, &own_seccomp_receiver_fd, &seccomp_notify_plugins,
                                     err);
      if (UNLIKELY (ret < 0))
        return ret;
    }

  /* This must be done before we enter a user namespace.  */
  ret = libcrun_set_rlimits (process->rlimits, process->rlimits_len, err);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = pipe (container_ret_status);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "pipe");
  pipefd0 = container_ret_status[0];
  pipefd1 = container_ret_status[1];

  /* If the new process block doesn't specify a SELinux label or AppArmor profile, then
     use the configuration from the original config file.  */
  if (container->container_def->process)
    {
      if (process->selinux_label == NULL && container->container_def->process->selinux_label)
        process->selinux_label = xstrdup (container->container_def->process->selinux_label);

      if (process->apparmor_profile == NULL && container->container_def->process->apparmor_profile)
        process->apparmor_profile = xstrdup (container->container_def->process->apparmor_profile);
    }

  ret = initialize_security (process, err);
  if (UNLIKELY (ret < 0))
    return ret;

+ pid = libcrun_join_process (container, status.pid, &status, context->detach, process->terminal ? &terminal_fd : NULL,
                              err);
  if (UNLIKELY (pid < 0))
    return pid;

  /* Process to exec.  */
  if (pid == 0)
    {
      size_t i;
      uid_t container_uid = process->user ? process->user->uid : 0;
      gid_t container_gid = process->user ? process->user->gid : 0;
      const char *cwd;
      runtime_spec_schema_config_schema_process_capabilities *capabilities = NULL;
      char **seccomp_flags = NULL;
      size_t seccomp_flags_len = 0;
      pid_t own_pid = 0;

      TEMP_FAILURE_RETRY (close (pipefd0));
      pipefd0 = -1;

      TEMP_FAILURE_RETRY (read (pipefd1, &own_pid, sizeof (own_pid)));

      cwd = process->cwd ? process->cwd : "/";
      if (chdir (cwd) < 0)
        libcrun_fail_with_error (errno, "chdir");

      ret = unblock_signals (err);
      if (UNLIKELY (ret < 0))
        return ret;

      ret = clearenv ();
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, 0, "clearenv");

      if (process->env_len)
        {
          for (i = 0; i < process->env_len; i++)
            if (putenv (process->env[i]) < 0)
              libcrun_fail_with_error (errno, "putenv `%s`", process->env[i]);
        }
      else if (container->container_def->process->env_len)
        {
          char *e;

          for (i = 0; i < container->container_def->process->env_len; i++)
            {
              e = container->container_def->process->env[i];
              if (putenv (e) < 0)
                libcrun_fail_with_error (errno, "putenv `%s`", e);
            }
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

      if (UNLIKELY (libcrun_set_selinux_exec_label (process, err) < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (UNLIKELY (libcrun_set_apparmor_profile (process, err) < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (container->container_def->linux && container->container_def->linux->seccomp)
        {
          seccomp_flags = container->container_def->linux->seccomp->flags;
          seccomp_flags_len = container->container_def->linux->seccomp->flags_len;
        }

-     // 得到执行命令
+     exec_path = find_executable (process->args[0], process->cwd);
      if (UNLIKELY (exec_path == NULL))
        {
          if (errno == ENOENT)
            crun_make_error (err, errno, "executable file `%s` not found in $PATH", process->args[0]);
          else
            crun_make_error (err, errno, "open executable");

          libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      if (container->container_def->linux && container->container_def->linux->personality)
        {
          ret = libcrun_set_personality (container->container_def->linux->personality, err);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = mark_for_close_fds_ge_than (context->preserve_fds + 3, err);
      if (UNLIKELY (ret < 0))
        libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);

      if (! process->no_new_privileges)
        {
          cleanup_free char *seccomp_fd_payload = NULL;
          size_t seccomp_fd_payload_len = 0;

          if (seccomp_receiver_fd >= 0)
            {
              ret = get_seccomp_receiver_fd_payload (container, "running", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }

          ret = libcrun_apply_seccomp (seccomp_fd, seccomp_receiver_fd, seccomp_fd_payload,
                                       seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&seccomp_fd);
          close_and_reset (&seccomp_receiver_fd);
        }

      ret = libcrun_container_setgroups (container, process, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (process->capabilities)
        capabilities = process->capabilities;
      else if (container->container_def->process)
        capabilities = container->container_def->process->capabilities;

      if (capabilities)
        {
          ret = libcrun_set_caps (capabilities, container_uid, container_gid, process->no_new_privileges, err);
          if (UNLIKELY (ret < 0))
            libcrun_fail_with_error ((*err)->status, "%s", (*err)->msg);
        }

      if (process->no_new_privileges)
        {
          cleanup_free char *seccomp_fd_payload = NULL;
          size_t seccomp_fd_payload_len = 0;

          if (seccomp_receiver_fd >= 0)
            {
              ret = get_seccomp_receiver_fd_payload (container, "running", own_pid, &seccomp_fd_payload, &seccomp_fd_payload_len, err);
              if (UNLIKELY (ret < 0))
                return ret;
            }
          ret = libcrun_apply_seccomp (seccomp_fd, seccomp_receiver_fd, seccomp_fd_payload,
                                       seccomp_fd_payload_len, seccomp_flags, seccomp_flags_len, err);
          if (UNLIKELY (ret < 0))
            return ret;

          close_and_reset (&seccomp_fd);
          close_and_reset (&seccomp_receiver_fd);
        }

      if (process->user)
        umask (process->user->umask_present ? process->user->umask : 0022);

      TEMP_FAILURE_RETRY (write (pipefd1, "0", 1));
      TEMP_FAILURE_RETRY (close (pipefd1));
      pipefd1 = -1;

-     // 执行exec中指定的命令
+     TEMP_FAILURE_RETRY (execv (exec_path, process->args));
      libcrun_fail_with_error (errno, "exec");
      _exit (EXIT_FAILURE);
    }
    
- // 父进程
  TEMP_FAILURE_RETRY (close (pipefd1));
  pipefd1 = -1;

  TEMP_FAILURE_RETRY (write (pipefd0, &pid, sizeof (pid)));

  if (seccomp_fd >= 0)
    close_and_reset (&seccomp_fd);

  if (terminal_fd >= 0)
    {
      unsigned short rows = 0, cols = 0;

      if (process->console_size)
        {
          cols = process->console_size->width;
          rows = process->console_size->height;
        }

      ret = libcrun_terminal_setup_size (terminal_fd, rows, cols, err);
      if (UNLIKELY (ret < 0))
        return ret;

      if (context->console_socket)
        {
          int ret;
          cleanup_close int console_socket_fd = open_unix_domain_client_socket (context->console_socket, 0, err);
          if (UNLIKELY (console_socket_fd < 0))
            return console_socket_fd;
          ret = send_fd_to_socket (console_socket_fd, terminal_fd, err);
          if (UNLIKELY (ret < 0))
            return ret;
          close_and_reset (&terminal_fd);
        }
      else
        {
          ret = libcrun_setup_terminal_ptmx (terminal_fd, &orig_terminal, err);
          if (UNLIKELY (ret < 0))
            {
              flush_fd_to_err (context, terminal_fd);
              return ret;
            }
        }
    }

  ret = TEMP_FAILURE_RETRY (read (pipefd0, &b, sizeof (b)));
  TEMP_FAILURE_RETRY (close (pipefd0));
  pipefd0 = -1;
  if (ret != 1 || b != '0')
    ret = -1;
  else
    {
      /* Let's receive the seccomp notify fd and handle it as part of wait_for_process().  */
      if (own_seccomp_receiver_fd >= 0)
        {
          seccomp_notify_fd = receive_fd_from_socket (own_seccomp_receiver_fd, err);
          if (UNLIKELY (seccomp_notify_fd < 0))
            return seccomp_notify_fd;

          ret = close_and_reset (&own_seccomp_receiver_fd);
          if (UNLIKELY (ret < 0))
            return ret;
        }
      ret = wait_for_process (pid, context, terminal_fd, -1, -1, seccomp_notify_fd, seccomp_notify_plugins, err);
    }

  flush_fd_to_err (context, terminal_fd);
  return ret;
}
```
- libcrun_container_exec -> libcrun_join_process
```diff
int
libcrun_join_process (libcrun_container_t *container, pid_t pid_to_join, libcrun_container_status_t *status, int detach,
                      int *terminal_fd, libcrun_error_t *err)
{
  pid_t pid;
  int ret;
  int sync_socket_fd[2];
  int fds[10] = {
    -1,
  };
  int fds_joined[10] = {
    0,
  };
  runtime_spec_schema_config_schema *def = container->container_def;
  size_t i;
  cleanup_close int sync_fd = -1;

  if (! detach)
    {
      ret = prctl (PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      if (UNLIKELY (ret < 0))
        return crun_make_error (err, errno, "set child subreaper");
    }

  ret = socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sync_socket_fd);
  if (UNLIKELY (ret < 0))
    return crun_make_error (err, errno, "error creating socketpair");

  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      crun_make_error (err, errno, "fork");
      goto exit;
    }
  if (pid)
    {
      close_and_reset (&sync_socket_fd[1]);
      sync_fd = sync_socket_fd[0];
      return join_process_parent_helper (pid, sync_fd, status, terminal_fd, err);
    }

  close_and_reset (&sync_socket_fd[0]);
  sync_fd = sync_socket_fd[1];

  if (def->linux->namespaces_len >= 10)
    {
      crun_make_error (err, 0, "invalid configuration");
      goto exit;
    }

  for (i = 0; namespaces[i].ns_file; i++)
    {
      cleanup_free char *ns_join = NULL;

      xasprintf (&ns_join, "/proc/%d/ns/%s", pid_to_join, namespaces[i].ns_file);
      fds[i] = open (ns_join, O_RDONLY);
      if (UNLIKELY (fds[i] < 0))
        {
          /* If the namespace doesn't exist, just ignore it.  */
          if (errno == ENOENT)
            continue;
          ret = crun_make_error (err, errno, "open `%s`", ns_join);
          goto exit;
        }
    }

  for (i = 0; namespaces[i].ns_file; i++)
    {
      if (namespaces[i].value == CLONE_NEWUSER)
        continue;

      ret = setns (fds[i], 0);
      if (ret == 0)
        fds_joined[i] = 1;
    }
  for (i = 0; namespaces[i].ns_file; i++)
    {
      ret = setns (fds[i], 0);
      if (ret == 0)
        fds_joined[i] = 1;
    }
  for (i = 0; namespaces[i].ns_file; i++)
    {
      if (fds_joined[i])
        continue;
      ret = setns (fds[i], 0);
      if (UNLIKELY (ret < 0 && errno != EINVAL))
        {
          size_t j;
          bool found = false;

          for (j = 0; j < def->linux->namespaces_len; j++)
            {
              if (strcmp (namespaces[i].ns_file, def->linux->namespaces[j]->type) == 0)
                {
                  found = true;
                  break;
                }
            }
          if (! found)
            {
              /* It was not requested to create this ns, so just ignore it.  */
              fds_joined[i] = 1;
              continue;
            }
          crun_make_error (err, errno, "setns `%s`", namespaces[i].ns_file);
          goto exit;
        }
      fds_joined[i] = 1;
    }
  for (i = 0; namespaces[i].ns_file; i++)
    close_and_reset (&fds[i]);

  if (setsid () < 0)
    {
      crun_make_error (err, errno, "setsid");
      goto exit;
    }

  /* We need to fork once again to join the PID namespace.  */
  pid = fork ();
  if (UNLIKELY (pid < 0))
    {
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "1", 1));
      crun_make_error (err, errno, "fork");
      goto exit;
    }

  if (pid)
    {
      /* Just return the PID to the parent helper and exit.  */
      ret = TEMP_FAILURE_RETRY (write (sync_fd, "0", 1));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      ret = TEMP_FAILURE_RETRY (write (sync_fd, &pid, sizeof (pid)));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      _exit (EXIT_SUCCESS);
    }
  else
    {
      /* Inside the grandchild process.  The real process
         used for the container.  */
      int r = -1;
      cleanup_free char *pty = NULL;

      ret = TEMP_FAILURE_RETRY (read (sync_fd, &r, sizeof (r)));
      if (UNLIKELY (ret < 0))
        _exit (EXIT_FAILURE);

      if (terminal_fd)
        {
          cleanup_close int ptmx_fd = -1;

          ret = setsid ();
          if (ret < 0)
            {
              crun_make_error (err, errno, "setsid");
              send_error_to_sync_socket_and_die (sync_fd, true, err);
            }

          ret = set_id_init (container, err);
          if (UNLIKELY (ret < 0))
            send_error_to_sync_socket_and_die (sync_fd, true, err);

          ptmx_fd = open_terminal (container, &pty, err);
          if (UNLIKELY (ptmx_fd < 0))
            send_error_to_sync_socket_and_die (sync_fd, true, err);

          ret = send_fd_to_socket (sync_fd, ptmx_fd, err);
          if (UNLIKELY (ret < 0))
            send_error_to_sync_socket_and_die (sync_fd, true, err);
        }

      if (r < 0)
        _exit (EXIT_FAILURE);
    }

  return pid;

exit:
  if (sync_socket_fd[0] >= 0)
    TEMP_FAILURE_RETRY (close (sync_socket_fd[0]));
  if (sync_socket_fd[1] >= 0)
    TEMP_FAILURE_RETRY (close (sync_socket_fd[1]));
  for (i = 0; namespaces[i].ns_file; i++)
    if (fds[i] >= 0)
      TEMP_FAILURE_RETRY (close (fds[i]));
  return ret;
}
```
