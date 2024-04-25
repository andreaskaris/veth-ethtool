package pod

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

var fakeCrictl = func(parameters ...string) ([]byte, error) {
	if len(parameters) == 3 && parameters[0] == "pods" && parameters[1] == "-o" && parameters[2] == "json" {
		return []byte(podsOutput), nil
	}
	if len(parameters) == 4 && parameters[0] == "inspectp" && parameters[1] == "-o" && parameters[2] == "json" &&
		parameters[3] == "fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410" {
		return []byte(podInspect), nil
	}
	return nil, fmt.Errorf("invalid input for fakeCrictlPods: %v", parameters)
}

var fakelistNetnsIDs = func(dir string) (map[string]int, error) {
	return map[string]int{
		"cni-6c2f3f24-c065-fe4d-c5d6-849f28acc7de": 4,
		"cni-invalid": 1,
	}, nil
}

func TestGetOwnerOfLink(t *testing.T) {
	crictl = fakeCrictl
	listNetnsIDs = fakelistNetnsIDs

	goodVeth := netlink.Veth{}
	goodVeth.NetNsID = 4
	badVeth := netlink.Veth{}
	badVeth.NetNsID = 1
	tcs := []struct {
		link   netlink.Link
		podID  string
		errStr string
	}{
		{&goodVeth, "fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410", ""},
		{&badVeth, "", "could not find a pod for netns"},
	}
	for i, tc := range tcs {
		p, err := GetOwnerOfLink(tc.link)
		if tc.errStr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.errStr) {
				t.Fatalf("Get(%d): expected to see error %q but got %q", i, tc.errStr, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Get(%d): expected to see no error but got %q", i, err)
		}
		if p.ID != tc.podID {
			t.Fatalf("Get(%d): expected to get pod with PID %q but got %q", i, tc.podID, p.ID)
		}
	}
}

const (
	podsOutput = `{
  "items": [
    {
      "id": "fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410",
      "metadata": {
        "name": "red-deployment-5bc7b56845-cgt7w",
        "uid": "0e760759-7576-4c0b-89d0-bf5c9539026e",
        "namespace": "test-ns-fc5ef8f4",
        "attempt": 0
      },
      "state": "SANDBOX_READY",
      "createdAt": "1714039221254165717",
      "labels": {
        "app": "test-app",
        "io.kubernetes.pod.name": "red-deployment-5bc7b56845-cgt7w",
        "io.kubernetes.pod.namespace": "test-ns-fc5ef8f4",
        "io.kubernetes.pod.uid": "0e760759-7576-4c0b-89d0-bf5c9539026e",
        "pod-template-hash": "5bc7b56845"
      },
      "annotations": {
        "kubernetes.io/config.seen": "2024-04-25T10:00:20.942545606Z",
        "kubernetes.io/config.source": "api"
      },
      "runtimeHandler": ""
    }
  ]
}`

	podInspect = `{
  "status": {
    "id": "fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410",
    "metadata": {
      "attempt": 0,
      "name": "red-deployment-5bc7b56845-cgt7w",
      "namespace": "test-ns-fc5ef8f4",
      "uid": "0e760759-7576-4c0b-89d0-bf5c9539026e"
    },
    "state": "SANDBOX_READY",
    "createdAt": "2024-04-25T10:00:21.254165717Z",
    "network": {
      "additionalIps": [],
      "ip": "10.244.0.9"
    },
    "linux": {
      "namespaces": {
        "options": {
          "ipc": "POD",
          "network": "POD",
          "pid": "CONTAINER",
          "targetId": "",
          "usernsOptions": null
        }
      }
    },
    "labels": {
      "app": "test-app",
      "io.kubernetes.pod.name": "red-deployment-5bc7b56845-cgt7w",
      "io.kubernetes.pod.namespace": "test-ns-fc5ef8f4",
      "io.kubernetes.pod.uid": "0e760759-7576-4c0b-89d0-bf5c9539026e",
      "pod-template-hash": "5bc7b56845"
    },
    "annotations": {
      "kubernetes.io/config.seen": "2024-04-25T10:00:20.942545606Z",
      "kubernetes.io/config.source": "api"
    },
    "runtimeHandler": ""
  },
  "info": {
    "pid": 6075,
    "processStatus": "running",
    "netNamespaceClosed": false,
    "image": "registry.k8s.io/pause:3.7",
    "snapshotKey": "fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410",
    "snapshotter": "overlayfs",
    "runtimeHandler": "",
    "runtimeType": "io.containerd.runc.v2",
    "runtimeOptions": {
      "systemd_cgroup": true
    },
    "config": {
      "metadata": {
        "name": "red-deployment-5bc7b56845-cgt7w",
        "uid": "0e760759-7576-4c0b-89d0-bf5c9539026e",
        "namespace": "test-ns-fc5ef8f4"
      },
      "hostname": "red-deployment-5bc7b56845-cgt7w",
      "log_directory": "/var/log/pods/test-ns-fc5ef8f4_red-deployment-5bc7b56845-cgt7w_0e760759-7576-4c0b-89d0-bf5c9539026e",
      "dns_config": {
        "servers": [
          "10.96.0.10"
        ],
        "searches": [
          "test-ns-fc5ef8f4.svc.cluster.local",
          "svc.cluster.local",
          "cluster.local",
          "dns.podman"
        ],
        "options": [
          "ndots:5"
        ]
      },
      "labels": {
        "app": "test-app",
        "io.kubernetes.pod.name": "red-deployment-5bc7b56845-cgt7w",
        "io.kubernetes.pod.namespace": "test-ns-fc5ef8f4",
        "io.kubernetes.pod.uid": "0e760759-7576-4c0b-89d0-bf5c9539026e",
        "pod-template-hash": "5bc7b56845"
      },
      "annotations": {
        "kubernetes.io/config.seen": "2024-04-25T10:00:20.942545606Z",
        "kubernetes.io/config.source": "api"
      },
      "linux": {
        "cgroup_parent": "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod0e760759_7576_4c0b_89d0_bf5c9539026e.slice",
        "security_context": {
          "namespace_options": {
            "pid": 1
          },
          "seccomp": {}
        },
        "overhead": {},
        "resources": {
          "cpu_period": 100000,
          "cpu_shares": 2
        }
      }
    },
    "runtimeSpec": {
      "ociVersion": "1.0.2-dev",
      "process": {
        "user": {
          "uid": 65535,
          "gid": 65535,
          "additionalGids": [
            65535
          ]
        },
        "args": [
          "/pause"
        ],
        "env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "cwd": "/",
        "capabilities": {
          "bounding": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
          ],
          "effective": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
          ],
          "permitted": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
          ]
        },
        "noNewPrivileges": true,
        "oomScoreAdj": 100
      },
      "root": {
        "path": "rootfs",
        "readonly": true
      },
      "hostname": "red-deployment-5bc7b56845-cgt7w",
      "mounts": [
        {
          "destination": "/proc",
          "type": "proc",
          "source": "proc",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        },
        {
          "destination": "/dev",
          "type": "tmpfs",
          "source": "tmpfs",
          "options": [
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
          ]
        },
        {
          "destination": "/dev/pts",
          "type": "devpts",
          "source": "devpts",
          "options": [
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
          ]
        },
        {
          "destination": "/dev/shm",
          "type": "tmpfs",
          "source": "shm",
          "options": [
            "nosuid",
            "noexec",
            "nodev",
            "mode=1777",
            "size=65536k"
          ]
        },
        {
          "destination": "/dev/mqueue",
          "type": "mqueue",
          "source": "mqueue",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        },
        {
          "destination": "/sys",
          "type": "sysfs",
          "source": "sysfs",
          "options": [
            "nosuid",
            "noexec",
            "nodev",
            "ro"
          ]
        },
        {
          "destination": "/dev/shm",
          "type": "bind",
          "source": "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410/shm",
          "options": [
            "rbind",
            "ro"
          ]
        },
        {
          "destination": "/etc/resolv.conf",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410/resolv.conf",
          "options": [
            "rbind",
            "ro"
          ]
        }
      ],
      "annotations": {
        "io.kubernetes.cri.container-type": "sandbox",
        "io.kubernetes.cri.sandbox-cpu-period": "100000",
        "io.kubernetes.cri.sandbox-cpu-quota": "0",
        "io.kubernetes.cri.sandbox-cpu-shares": "2",
        "io.kubernetes.cri.sandbox-id": "fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410",
        "io.kubernetes.cri.sandbox-log-directory": "/var/log/pods/test-ns-fc5ef8f4_red-deployment-5bc7b56845-cgt7w_0e760759-7576-4c0b-89d0-bf5c9539026e",
        "io.kubernetes.cri.sandbox-memory": "0",
        "io.kubernetes.cri.sandbox-name": "red-deployment-5bc7b56845-cgt7w",
        "io.kubernetes.cri.sandbox-namespace": "test-ns-fc5ef8f4",
        "io.kubernetes.cri.sandbox-uid": "0e760759-7576-4c0b-89d0-bf5c9539026e"
      },
      "linux": {
        "resources": {
          "devices": [
            {
              "allow": false,
              "access": "rwm"
            }
          ],
          "cpu": {
            "shares": 2
          }
        },
        "cgroupsPath": "kubelet-kubepods-besteffort-pod0e760759_7576_4c0b_89d0_bf5c9539026e.slice:cri-containerd:fce6f52914c45673e3b34d9ede950fc24951c31380818f3e256e93eb0fe1f410",
        "namespaces": [
          {
            "type": "pid"
          },
          {
            "type": "ipc"
          },
          {
            "type": "uts"
          },
          {
            "type": "mount"
          },
          {
            "type": "network",
            "path": "/var/run/netns/cni-6c2f3f24-c065-fe4d-c5d6-849f28acc7de"
          }
        ],
        "seccomp": {
          "defaultAction": "SCMP_ACT_ERRNO",
          "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_X86",
            "SCMP_ARCH_X32"
          ],
          "syscalls": [
            {
              "names": [
                "accept",
                "accept4",
                "access",
                "adjtimex",
                "alarm",
                "bind",
                "brk",
                "capget",
                "capset",
                "chdir",
                "chmod",
                "chown",
                "chown32",
                "clock_adjtime",
                "clock_adjtime64",
                "clock_getres",
                "clock_getres_time64",
                "clock_gettime",
                "clock_gettime64",
                "clock_nanosleep",
                "clock_nanosleep_time64",
                "close",
                "close_range",
                "connect",
                "copy_file_range",
                "creat",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_pwait2",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat",
                "faccessat2",
                "fadvise64",
                "fadvise64_64",
                "fallocate",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchown",
                "fchown32",
                "fchownat",
                "fcntl",
                "fcntl64",
                "fdatasync",
                "fgetxattr",
                "flistxattr",
                "flock",
                "fork",
                "fremovexattr",
                "fsetxattr",
                "fstat",
                "fstat64",
                "fstatat64",
                "fstatfs",
                "fstatfs64",
                "fsync",
                "ftruncate",
                "ftruncate64",
                "futex",
                "futex_time64",
                "futex_waitv",
                "futimesat",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "getegid32",
                "geteuid",
                "geteuid32",
                "getgid",
                "getgid32",
                "getgroups",
                "getgroups32",
                "getitimer",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresgid32",
                "getresuid",
                "getresuid32",
                "getrlimit",
                "get_robust_list",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "get_thread_area",
                "gettid",
                "gettimeofday",
                "getuid",
                "getuid32",
                "getxattr",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "ioctl",
                "io_destroy",
                "io_getevents",
                "io_pgetevents",
                "io_pgetevents_time64",
                "ioprio_get",
                "ioprio_set",
                "io_setup",
                "io_submit",
                "io_uring_enter",
                "io_uring_register",
                "io_uring_setup",
                "ipc",
                "kill",
                "landlock_add_rule",
                "landlock_create_ruleset",
                "landlock_restrict_self",
                "lchown",
                "lchown32",
                "lgetxattr",
                "link",
                "linkat",
                "listen",
                "listxattr",
                "llistxattr",
                "_llseek",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "lstat",
                "lstat64",
                "madvise",
                "membarrier",
                "memfd_create",
                "memfd_secret",
                "mincore",
                "mkdir",
                "mkdirat",
                "mknod",
                "mknodat",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "mmap2",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedreceive_time64",
                "mq_timedsend",
                "mq_timedsend_time64",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "nanosleep",
                "newfstatat",
                "_newselect",
                "open",
                "openat",
                "openat2",
                "pause",
                "pidfd_open",
                "pidfd_send_signal",
                "pipe",
                "pipe2",
                "pkey_alloc",
                "pkey_free",
                "pkey_mprotect",
                "poll",
                "ppoll",
                "ppoll_time64",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "process_mrelease",
                "pselect6",
                "pselect6_time64",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "read",
                "readahead",
                "readlink",
                "readlinkat",
                "readv",
                "recv",
                "recvfrom",
                "recvmmsg",
                "recvmmsg_time64",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "rename",
                "renameat",
                "renameat2",
                "restart_syscall",
                "rmdir",
                "rseq",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigqueueinfo",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_sigtimedwait_time64",
                "rt_tgsigqueueinfo",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getscheduler",
                "sched_rr_get_interval",
                "sched_rr_get_interval_time64",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "semtimedop_time64",
                "send",
                "sendfile",
                "sendfile64",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "setfsgid",
                "setfsgid32",
                "setfsuid",
                "setfsuid32",
                "setgid",
                "setgid32",
                "setgroups",
                "setgroups32",
                "setitimer",
                "setpgid",
                "setpriority",
                "setregid",
                "setregid32",
                "setresgid",
                "setresgid32",
                "setresuid",
                "setresuid32",
                "setreuid",
                "setreuid32",
                "setrlimit",
                "set_robust_list",
                "setsid",
                "setsockopt",
                "set_thread_area",
                "set_tid_address",
                "setuid",
                "setuid32",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "sigprocmask",
                "sigreturn",
                "socket",
                "socketcall",
                "socketpair",
                "splice",
                "stat",
                "stat64",
                "statfs",
                "statfs64",
                "statx",
                "symlink",
                "symlinkat",
                "sync",
                "sync_file_range",
                "syncfs",
                "sysinfo",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_gettime64",
                "timer_settime",
                "timer_settime64",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_gettime64",
                "timerfd_settime",
                "timerfd_settime64",
                "times",
                "tkill",
                "truncate",
                "truncate64",
                "ugetrlimit",
                "umask",
                "uname",
                "unlink",
                "unlinkat",
                "utime",
                "utimensat",
                "utimensat_time64",
                "utimes",
                "vfork",
                "vmsplice",
                "wait4",
                "waitid",
                "waitpid",
                "write",
                "writev"
              ],
              "action": "SCMP_ACT_ALLOW"
            },
            {
              "names": [
                "personality"
              ],
              "action": "SCMP_ACT_ALLOW",
              "args": [
                {
                  "index": 0,
                  "value": 0,
                  "op": "SCMP_CMP_EQ"
                }
              ]
            },
            {
              "names": [
                "personality"
              ],
              "action": "SCMP_ACT_ALLOW",
              "args": [
                {
                  "index": 0,
                  "value": 8,
                  "op": "SCMP_CMP_EQ"
                }
              ]
            },
            {
              "names": [
                "personality"
              ],
              "action": "SCMP_ACT_ALLOW",
              "args": [
                {
                  "index": 0,
                  "value": 131072,
                  "op": "SCMP_CMP_EQ"
                }
              ]
            },
            {
              "names": [
                "personality"
              ],
              "action": "SCMP_ACT_ALLOW",
              "args": [
                {
                  "index": 0,
                  "value": 131080,
                  "op": "SCMP_CMP_EQ"
                }
              ]
            },
            {
              "names": [
                "personality"
              ],
              "action": "SCMP_ACT_ALLOW",
              "args": [
                {
                  "index": 0,
                  "value": 4294967295,
                  "op": "SCMP_CMP_EQ"
                }
              ]
            },
            {
              "names": [
                "ptrace"
              ],
              "action": "SCMP_ACT_ALLOW"
            },
            {
              "names": [
                "arch_prctl",
                "modify_ldt"
              ],
              "action": "SCMP_ACT_ALLOW"
            },
            {
              "names": [
                "chroot"
              ],
              "action": "SCMP_ACT_ALLOW"
            },
            {
              "names": [
                "clone"
              ],
              "action": "SCMP_ACT_ALLOW",
              "args": [
                {
                  "index": 0,
                  "value": 2114060288,
                  "op": "SCMP_CMP_MASKED_EQ"
                }
              ]
            },
            {
              "names": [
                "clone3"
              ],
              "action": "SCMP_ACT_ERRNO",
              "errnoRet": 38
            }
          ]
        },
        "maskedPaths": [
          "/proc/acpi",
          "/proc/asound",
          "/proc/kcore",
          "/proc/keys",
          "/proc/latency_stats",
          "/proc/timer_list",
          "/proc/timer_stats",
          "/proc/sched_debug",
          "/sys/firmware",
          "/proc/scsi"
        ],
        "readonlyPaths": [
          "/proc/bus",
          "/proc/fs",
          "/proc/irq",
          "/proc/sys",
          "/proc/sysrq-trigger"
        ]
      }
    },
    "cniResult": {
      "Interfaces": {
        "eth0": {
          "IPConfigs": [
            {
              "IP": "10.244.0.9",
              "Gateway": "10.244.0.1"
            }
          ],
          "Mac": "02:ed:dc:38:4b:9b",
          "Sandbox": "/var/run/netns/cni-6c2f3f24-c065-fe4d-c5d6-849f28acc7de"
        },
        "lo": {
          "IPConfigs": [
            {
              "IP": "127.0.0.1",
              "Gateway": ""
            },
            {
              "IP": "::1",
              "Gateway": ""
            }
          ],
          "Mac": "00:00:00:00:00:00",
          "Sandbox": "/var/run/netns/cni-6c2f3f24-c065-fe4d-c5d6-849f28acc7de"
        },
        "veth57ab7399": {
          "IPConfigs": null,
          "Mac": "02:a6:09:e1:2c:b0",
          "Sandbox": ""
        }
      },
      "DNS": [
        {},
        {}
      ],
      "Routes": [
        {
          "dst": "0.0.0.0/0"
        }
      ]
    }
  }
}`
)
