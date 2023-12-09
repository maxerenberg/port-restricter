#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define log_warn(args...) fprintf(stderr, args)
#define log_info(args...) if (verbose) fprintf(stderr, args)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))

static bool verbose = false;

static bool parse_port(const char *s, in_port_t *port) {
    char *endptr = NULL;
    const long parsed = strtol(s, &endptr, 10);
    if (*endptr != '\0' || parsed <= 0 || parsed >= USHRT_MAX) {
        log_warn("Not a valid port number: %s\n", s);
        return false;
    }
    *port = (in_port_t)parsed;
    return true;
}

static void print_usage(const char *arg0) {
    fprintf(stderr, "Usage: %s [-v] -p <port> cmd [args...]\n", arg0);
}

static void perror_and_exit(const char *s) {
    perror(s);
    exit(EXIT_FAILURE);
}

static int pidfd_open(pid_t pid, unsigned int flags) {
    return (int)syscall(SYS_pidfd_open, pid, flags);
}

static int pidfd_getfd(int pidfd, int targetfd, unsigned int flags) {
    return (int)syscall(SYS_pidfd_getfd, pidfd, targetfd, flags);
}

static bool handle_notif(int pidfd,
                         int notify_fd,
                         in_port_t port,
                         struct seccomp_notif *req)
{
    if (req->data.nr != __NR_bind) {
        log_warn("Received unexpected syscall: %d\n", req->data.nr);
        return false;
    }
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
        struct sockaddr_un un;
    } u = {};
    const int arg_sockfd = (int)req->data.args[0];
    const struct sockaddr *arg_addr = (const struct sockaddr*)req->data.args[1];
    const socklen_t arg_addrlen = (socklen_t)req->data.args[2];
    if (arg_addrlen < sizeof(sa_family_t)) {
        log_info("addrlen of %u is too small\n", arg_addrlen);
        return false;
    } else if (arg_addrlen > sizeof(u)) {
        log_info("addrlen of %u is too large\n", arg_addrlen);
        return false;
    }
    // Read the task's memory to see the values of their args
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/mem", req->pid);
    const int mem_fd = open(path, O_RDONLY);
    if (mem_fd < 0) {
        log_info("Failed to open %s\n", path);
        return false;
    }
    bool success = false;
    ssize_t num_read = 0;
    int sockfd = -1;
    if (seccomp_notify_id_valid(notify_fd, req->id) < 0) {
        log_info("Task exited after we opened its memory\n");
        goto out;
    }
    num_read = pread(mem_fd, &u, arg_addrlen, (off_t)arg_addr);
    if (num_read != arg_addrlen) {
        if (num_read < 0) {
            perror("pread");
        } else {
            log_info("Failed to read task's memory\n");
        }
        goto out;
    }
    // Only perform port check for Internet domain sockets
    if (u.in.sin_family == AF_INET || u.in.sin_family == AF_INET6) {
        if ((u.in.sin_family == AF_INET && arg_addrlen != sizeof(struct sockaddr_in)) ||
            (u.in.sin_family == AF_INET6 && arg_addrlen != sizeof(struct sockaddr_in6)))
        {
            log_info("Wrong struct size for address family\n");
            goto out;
        }
        if (ntohs(u.in.sin_port) != port) {
            log_info("Denying request to bind to port %hu\n", ntohs(u.in.sin_port));
            goto out;
        }
    }
    sockfd = pidfd_getfd(pidfd, arg_sockfd, 0);
    if (sockfd < 0) {
        perror("pidfd_getfd");
        goto out;
    }
    if (bind(sockfd, (struct sockaddr*)&u, arg_addrlen) < 0) {
        perror("bind");
        goto out;
    }
    success = true;
out:
    if (sockfd != -1) {
        close(sockfd);
    }
    close(mem_fd);
    return success;
}

static void parent_body(int child_to_parent[2],
                        int parent_to_child[2],
                        pid_t pid,
                        in_port_t port)
{
    close(child_to_parent[1]);
    close(parent_to_child[0]);
    int notify_fd = -1;
    ssize_t num_read = 0;
    ssize_t num_written = 0;
    const char dummy = 0;
    int pidfd = -1;
    struct seccomp_notif *req = NULL;
    struct seccomp_notif_resp *resp = NULL;
    int rc = 0;
    bool success = false;

    pidfd = pidfd_open(pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open");
        goto out;
    }
    // Get notify_fd value from child
    num_read = read(child_to_parent[0], &notify_fd, sizeof(notify_fd));
    close(child_to_parent[0]);
    if (num_read != sizeof(notify_fd)) {
        if (num_read >= 0) {
            log_warn("Failed to read notify_fd from child\n");
        } else {
            perror("read");
        }
        goto out;
    }
    notify_fd = pidfd_getfd(pidfd, notify_fd, 0);
    if (notify_fd < 0) {
        perror("pidfd_getfd");
        goto out;
    }
    // Tell child that they can continue
    num_written = write(parent_to_child[1], &dummy, sizeof(dummy));
    close(parent_to_child[1]);
    if (num_written != sizeof(dummy)) {
        if (num_written >= 0) {
            log_warn("Failed to write dummy to child\n");
        } else {
            perror("write");
        }
        goto out;
    }
    rc = seccomp_notify_alloc(&req, &resp);
    if (rc < 0) {
        log_warn("seccomp_notify_alloc: %s\n", strerror(-rc));
        goto out;
    }
    struct pollfd fds[] = {
        {.fd = pidfd, .events = POLLIN},
        {.fd = notify_fd, .events = POLLIN}
    };
    for (;;) {
        if (poll(fds, ARRAY_SIZE(fds), -1) < 0) {
            perror("poll");
            goto out;
        }
        for (nfds_t i = 0; i < ARRAY_SIZE(fds); i++) {
            if (fds[i].revents == 0) {
                continue;
            }
            if (fds[i].fd == pidfd) {
                log_info("Child process exited\n");
                success = true;
                goto out;
            } else if (fds[i].fd == notify_fd) {
                // From man:seccomp_unotify(2):
                // "This structure must be zeroed out before the call"
                memset(req, 0, sizeof(*req));
                rc = seccomp_notify_receive(notify_fd, req);
                if (rc < 0) {
                    if (rc == -ECANCELED) {
                        perror("seccomp_notify_receive");
                    } else {
                        log_warn("seccomp_notify_receive: %s\n", strerror(-rc));
                    }
                    goto out;
                }
                resp->id = req->id;
                resp->flags = 0;
                resp->val = 0;
                resp->error = 0;
                if (!handle_notif(pidfd, notify_fd, port, req)) {
                    resp->error = -EPERM;
                }
                rc = seccomp_notify_respond(notify_fd, resp);
                if (rc < 0) {
                    log_warn("seccomp_notify_respond: %s\n", strerror(-rc));
                    goto out;
                }
            }
        }
    }
out:
    if (req && resp) seccomp_notify_free(req, resp);
    if (notify_fd >= 0) close(notify_fd);
    if (pidfd >= 0) close(pidfd);
    if (!success) exit(EXIT_FAILURE);
}

static void child_body(int child_to_parent[2],
                       int parent_to_child[2],
                       char *argv[])
{
    close(child_to_parent[0]);
    close(parent_to_child[1]);
    int notify_fd = -1;
    int rc = 0;
    scmp_filter_ctx ctx = NULL;
    ssize_t num_written = 0;
    char dummy = 0;
    ssize_t num_read = 0;
    bool success = false;

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        log_warn("seccomp_init failed\n");
        goto out;
    }
    rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(bind), 0);
    if (rc < 0) {
        log_warn("seccomp_rule_add: %s\n", strerror(-rc));
        goto out;
    }
    rc = seccomp_load(ctx);
    if (rc < 0) {
        log_warn("seccomp_load: %s\n", strerror(-rc));
        goto out;
    }
    notify_fd = seccomp_notify_fd(ctx);
    if (notify_fd < 0) {
        log_warn("seccomp_notify_fd returned %d\n", notify_fd);
        goto out;
    }
    // send notify_fd to parent
    num_written = write(child_to_parent[1], &notify_fd, sizeof(notify_fd));
    if (num_written != sizeof(notify_fd)) {
        if (num_written >= 0) {
            log_warn("Failed to write notify_fd to parent\n");
        } else {
            perror("write");
        }
        goto out;
    }
    close(child_to_parent[1]);
    num_read = read(parent_to_child[0], &dummy, sizeof(dummy));
    close(parent_to_child[0]);
    if (num_read != sizeof(dummy)) {
        if (num_read >= 0) {
            log_warn("Failed to read dummy from parent\n");
        } else {
            perror("read");
        }
        goto out;
    }
    success = true;
out:
    if (notify_fd != -1) close(notify_fd);
    if (ctx) seccomp_release(ctx);
    if (!success) exit(EXIT_FAILURE);
    execvp(argv[0], argv);
    perror_and_exit("execv");
}

int main(int argc, char *argv[]) {
    bool parsed_port = false;
    in_port_t port;
    int opt;
    while ((opt = getopt(argc, argv, "p:v")) != -1) {
        switch (opt) {
            case 'p':
                parsed_port = parse_port(optarg, &port);
                if (!parsed_port) {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'v':
                verbose = true;
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!parsed_port || optind >= argc) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    // Used to send the notify_fd from the child to the parent
    int child_to_parent[2];
    if (pipe(child_to_parent) < 0) {
        perror_and_exit("pipe");
    }
    // Used by the parent to tell the child when it's ready
    int parent_to_child[2];
    if (pipe(parent_to_child) < 0) {
        perror_and_exit("pipe");
    }

    const pid_t pid = fork();
    if (pid < 0) {
        perror_and_exit("fork");
    } else if (pid > 0) {
        parent_body(child_to_parent, parent_to_child, pid, port);
    } else {
        child_body(child_to_parent, parent_to_child, argv + optind);
    }
}
