


//#include <linux/bpf.h>
//#include <linux/if_ether.h>
//#include <linux/if_packet.h>
//#include <linux/ip.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
//#include <linux/sched.h>
//#include <linux/nsproxy.h>
//#include <linux/pid_namespace.h>
//#include <linux/sched/task.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)

#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )

SEC("kprobe/sys_read")
int block_read(struct pt_regs *ctx)
{
    // Check if the file descriptor matches the one you want to block
    int fd = PT_REGS_PARM1(ctx);
    if (fd == 12) {
        // Block the read system call by returning an error code
        return -EPERM;
    }
    // Allow the read system call to proceed
    return 0;
}


// Based on sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_fchmodat/format
struct fchmodat_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dfd;
    int mode;
    char *filename;
    int mode2;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, char[64]);
    __uint(max_entries, 64);
} tech_talk SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int hello_tech_talk(struct fchmodat_args *ctx)
{
    int ret;
    u32 inputKey = 1;
    u32 keyOutput = 2;
    char valMyFileName[64];
    char valKernelFileName[64];
    char sendOK[64];
    char *tmpData;
    char *tmpData2;

    // GET FILENAME WHICH SOMEONE O PEN(FROM HOOK)
    ret = bpf_probe_read(&tmpData, sizeof(tmpData), &ctx->filename);
    if (ret != 0) {
        bpf_printk("ERROR Read");
    }

    ret = bpf_probe_read_str(valKernelFileName, sizeof(valKernelFileName), tmpData);
    if (ret < 0) {
       // bpf_printk("ERROR Read String");
    }

    // GET FILENAME FROM OUR CONFIG
    char *filename = bpf_map_lookup_elem(&tech_talk,&inputKey);
    if (!filename) {
        bpf_printk("ERROR Read problem with configmap");
    }

    ret = bpf_probe_read(&tmpData2, sizeof(tmpData2), &filename);
    if (ret != 0) {
        bpf_printk("ERROR Read2");
    }

    ret = bpf_probe_read_str(valMyFileName, sizeof(valMyFileName), tmpData2);
    if (ret < 0) {
        bpf_printk("ERROR Read String2");
    }

    if (compare(valKernelFileName, valMyFileName, 11) == 0) {
        // UPDATE MAP FOR USER SPACE PROGRAM
        ret = bpf_map_update_elem(&tech_talk, &keyOutput, &valMyFileName, BPF_ANY);
        if (ret != 0) {
            bpf_printk("ERROR during map update");
        }
        bpf_printk("Found unauthorized open my file, kill the process");
        bpf_printk("FileName: %s ",valKernelFileName);
        bpf_printk("PID: %d",bpf_get_current_pid_tgid());

        //KILL THE PROCESS WHO OPEN MY FILE
        bpf_send_signal(9);
    }
    return 0;
}


int compare(char src[64], char dst[64], int sizeVal) {
  int retVal = 0;
  for (int index=0;index<sizeVal;index++) {
      if (src[index] != dst[index]) {
        retVal = 1;
        break;
      }
  }
  return retVal;
}

char LICENSE[] SEC("license") = "GPL";
