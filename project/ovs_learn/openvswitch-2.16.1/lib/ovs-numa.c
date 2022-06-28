/*
 * Copyright (c) 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "ovs-numa.h"

#include <ctype.h>
#include <errno.h>
#ifdef __linux__
#include <dirent.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* __linux__ */

#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ovs_numa);

/* ovs-numa module
 * ===============
 *
 * This module stores the affinity information of numa nodes and cpu cores.
 * It also provides functions to bookkeep the pin of threads on cpu cores.
 *
 * It is assumed that the numa node ids and cpu core ids all start from 0.
 * There is no guarantee that node and cpu ids are numbered consecutively
 * So, for example, if two nodes exist with ids 0 and 8,
 * 'ovs_numa_get_n_nodes()' will return 2, no assumption of node numbering
 * should be made.
 *
 * NOTE, this module should only be used by the main thread.
 *
 * NOTE, if cpu hotplug is used 'all_numa_nodes' and 'all_cpu_cores' must be
 * invalidated when ever the system topology changes.  Support for detecting
 * topology changes has not been included. For now, add a TODO entry for
 * addressing it in the future.
 *
 * TODO: Fix ovs-numa when cpu hotplug is used.
 */


/* numa node. */
struct numa_node {
    struct hmap_node hmap_node;     /* In the 'all_numa_nodes'. */
    struct ovs_list cores;          /* List of cpu cores on the numa node. */
    int numa_id;                    /* numa node id. */
};

/* Cpu core on a numa node. */
struct cpu_core {
    struct hmap_node hmap_node;/* In the 'all_cpu_cores'. */
    struct ovs_list list_node; /* In 'numa_node->cores' list. */
    struct numa_node *numa;    /* numa node containing the core. */
    unsigned core_id;          /* Core id. */
};

/* Contains all 'struct numa_node's. */
static struct hmap all_numa_nodes = HMAP_INITIALIZER(&all_numa_nodes);
/* Contains all 'struct cpu_core's. */
static struct hmap all_cpu_cores = HMAP_INITIALIZER(&all_cpu_cores);
/* True if numa node and core info are correctly extracted. */
static bool found_numa_and_core;
/* True if the module was initialized with dummy options. In this case, the
 * module must not interact with the actual cpus/nodes in the system. */
static bool dummy_numa = false;
/* If 'dummy_numa' is true, contains a copy of the dummy numa configuration
 * parameter */
static char *dummy_config;

static struct numa_node *get_numa_by_numa_id(int numa_id);

#ifdef __linux__
/* Returns true if 'str' contains all digits.  Returns false otherwise. */
static bool
contain_all_digits(const char *str)
{
    return str[strspn(str, "0123456789")] == '\0';
}
#endif /* __linux__ */

static struct numa_node *
insert_new_numa_node(int numa_id)
{
    struct numa_node *n = xzalloc(sizeof *n);

    hmap_insert(&all_numa_nodes, &n->hmap_node, hash_int(numa_id, 0));
    ovs_list_init(&n->cores);
    n->numa_id = numa_id;

    return n;
}

static struct cpu_core *
insert_new_cpu_core(struct numa_node *n, unsigned core_id)
{
    struct cpu_core *c = xzalloc(sizeof *c);

    hmap_insert(&all_cpu_cores, &c->hmap_node, hash_int(core_id, 0));
    ovs_list_insert(&n->cores, &c->list_node);
    c->core_id = core_id;
    c->numa = n;

    return c;
}

/* Has the same effect as discover_numa_and_core(), but instead of
 * reading sysfs entries, extracts the info from the global variable
 * 'dummy_config', which is set with ovs_numa_set_dummy().
 *
 * 'dummy_config' lists the numa_ids of each CPU separated by a comma, e.g.
 * - "0,0,0,0": four cores on numa socket 0.
 * - "0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1": 16 cores on two numa sockets.
 * - "0,0,0,0,1,1,1,1": 8 cores on two numa sockets.
 * - "0,0,0,0,8,8,8,8": 8 cores on two numa sockets, non-contiguous.
 */
static void
discover_numa_and_core_dummy(void)
{
    char *conf = xstrdup(dummy_config);
    char *id, *saveptr = NULL;
    unsigned i = 0;

    for (id = strtok_r(conf, ",", &saveptr); id;
         id = strtok_r(NULL, ",", &saveptr)) {
        struct hmap_node *hnode;
        struct numa_node *n;
        long numa_id;

        numa_id = strtol(id, NULL, 10);
        if (numa_id < 0 || numa_id >= MAX_NUMA_NODES) {
            VLOG_WARN("Invalid numa node %ld", numa_id);
            continue;
        }

        hnode = hmap_first_with_hash(&all_numa_nodes, hash_int(numa_id, 0));

        if (hnode) {
            n = CONTAINER_OF(hnode, struct numa_node, hmap_node);
        } else {
            n = insert_new_numa_node(numa_id);
        }

        insert_new_cpu_core(n, i);

        i++;
    }

    free(conf);

}

#ifdef __linux__
/* Check if a CPU is detected and online. */
static int
cpu_detected(unsigned int core_id)
{
    char path[PATH_MAX];
    int len = snprintf(path, sizeof(path),
                       "/sys/devices/system/cpu/cpu%d/topology/core_id",
                       core_id);
    if (len <= 0 || (unsigned) len >= sizeof(path)) {
        return 0;
    }
    if (access(path, F_OK) != 0) {
        return 0;
    }

    return 1;
}
#endif /* __linux__ */

/* Discovers all numa nodes and the corresponding cpu cores.
 * Constructs the 'struct numa_node' and 'struct cpu_core'. */
static void
discover_numa_and_core(void)
{
#ifdef __linux__
    int i;
    DIR *dir;
    bool numa_supported = true;

    /* Check if NUMA supported on this system. */
    dir = opendir("/sys/devices/system/node");

    if (!dir && errno == ENOENT) {
        numa_supported = false;
    }
    if (dir) {
        closedir(dir);
    }

    for (i = 0; i < MAX_NUMA_NODES; i++) {
        char* path;

        if (numa_supported) {
            /* Constructs the path to node /sys/devices/system/nodeX. */
            path = xasprintf("/sys/devices/system/node/node%d", i);
        } else {
            path = xasprintf("/sys/devices/system/cpu/");
        }

        dir = opendir(path);

        /* Creates 'struct numa_node' if the 'dir' is non-null. */
        if (dir) {
            struct numa_node *n;
            struct dirent *subdir;

            n = insert_new_numa_node(i);

            while ((subdir = readdir(dir)) != NULL) {
                if (!strncmp(subdir->d_name, "cpu", 3)
                    && contain_all_digits(subdir->d_name + 3)) {
                    unsigned core_id;

                    core_id = strtoul(subdir->d_name + 3, NULL, 10);
                    if (cpu_detected(core_id)) {
                        insert_new_cpu_core(n, core_id);
                    }
                }
            }
            closedir(dir);
        } else if (errno != ENOENT) {
            VLOG_WARN("opendir(%s) failed (%s)", path,
                      ovs_strerror(errno));
        }

        free(path);
        if (!numa_supported) {
            break;
        }
    }
#endif /* __linux__ */
}

/* Gets 'struct cpu_core' by 'core_id'. */
/*******************************************************************************
 函数名称  :    get_core_by_core_id
 功能描述  :    根据core_id从all_cpu_cores获取核信息
 输入参数  :  	core_id---
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
static struct cpu_core*
get_core_by_core_id(unsigned core_id)
{
    /*每numa节点CPU核*/
    struct cpu_core *core;

    /*从all_cpu_cores中查询core_id是否存在*/
    HMAP_FOR_EACH_WITH_HASH (core, hmap_node, hash_int(core_id, 0),
                             &all_cpu_cores) {
        if (core->core_id == core_id) {
            return core;
        }
    }

    return NULL;
}

/* Gets 'struct numa_node' by 'numa_id'. */
static struct numa_node*
get_numa_by_numa_id(int numa_id)
{
    struct numa_node *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, hmap_node, hash_int(numa_id, 0),
                             &all_numa_nodes) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }

    return NULL;
}


/* Initializes the numa module. */
void
ovs_numa_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        const struct numa_node *n;

        if (dummy_numa) {
            discover_numa_and_core_dummy();
        } else {
            discover_numa_and_core();
        }

        HMAP_FOR_EACH(n, hmap_node, &all_numa_nodes) {
            VLOG_INFO("Discovered %"PRIuSIZE" CPU cores on NUMA node %d",
                      ovs_list_size(&n->cores), n->numa_id);
        }

        VLOG_INFO("Discovered %"PRIuSIZE" NUMA nodes and %"PRIuSIZE" CPU cores",
                   hmap_count(&all_numa_nodes), hmap_count(&all_cpu_cores));

        if (hmap_count(&all_numa_nodes) && hmap_count(&all_cpu_cores)) {
            found_numa_and_core = true;
        }

        ovsthread_once_done(&once);
    }
}

/* Extracts the numa node and core info from the 'config'.  This is useful for
 * testing purposes.  The function must be called once, before ovs_numa_init().
 *
 * The format of 'config' is explained in the comment above
 * discover_numa_and_core_dummy().*/
void
ovs_numa_set_dummy(const char *config)
{
    dummy_numa = true;
    ovs_assert(config);
    free(dummy_config);
    dummy_config = xstrdup(config);
}

bool
ovs_numa_numa_id_is_valid(int numa_id)
{
    return found_numa_and_core && numa_id < ovs_numa_get_n_numas();
}

bool
ovs_numa_core_id_is_valid(unsigned core_id)
{
    return found_numa_and_core && core_id < ovs_numa_get_n_cores();
}

/* Returns the number of numa nodes. */
int
ovs_numa_get_n_numas(void)
{
    return found_numa_and_core ? hmap_count(&all_numa_nodes)
                               : OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores. */
int
ovs_numa_get_n_cores(void)
{
    return found_numa_and_core ? hmap_count(&all_cpu_cores)
                               : OVS_CORE_UNSPEC;
}

/* Given 'core_id', returns the corresponding numa node id.  Returns
 * OVS_NUMA_UNSPEC if 'core_id' is invalid. */
int
ovs_numa_get_numa_id(unsigned core_id)
{
    struct cpu_core *core = get_core_by_core_id(core_id);

    if (core) {
        return core->numa->numa_id;
    }

    return OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores on numa node.  Returns OVS_CORE_UNSPEC
 * if 'numa_id' is invalid. */
int
ovs_numa_get_n_cores_on_numa(int numa_id)
{
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        return ovs_list_size(&numa->cores);
    }

    return OVS_CORE_UNSPEC;
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_create
 功能描述  :    
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
static struct ovs_numa_dump *
ovs_numa_dump_create(void)
{
    /*申请一个numa 结构*/
    struct ovs_numa_dump *dump = xmalloc(sizeof *dump);

    hmap_init(&dump->cores);
    hmap_init(&dump->numas);

    return dump;
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_add
 功能描述  :    逻辑核id填入numa节点，numa节点若为新增填入dump，numa管理图
 输入参数  :    dump---numa dump结构
                numa_id---numa id
                core_id---逻辑核id
 输出参数  :    
 返 回 值  :     无
*******************************************************************************/
static void
ovs_numa_dump_add(struct ovs_numa_dump *dump, int numa_id, int core_id)
{
    /*numa 逻辑核 id 对，记录核id与numa id*/
    struct ovs_numa_info_core *c = xzalloc(sizeof *c);

    /*一个numa节点*/
    struct ovs_numa_info_numa *n;

    /*CPU核信息，记录核id与所在numa id*/
    c->numa_id = numa_id;
    c->core_id = core_id;

    /*核信息插入所在numa的核信息链表，hmap插入*/
    hmap_insert(&dump->cores, &c->hmap_node, hash_2words(numa_id, core_id));

    HMAP_FOR_EACH_WITH_HASH (n, hmap_node, hash_int(numa_id, 0),
                             &dump->numas) {
        /*遍历dump 记录的numa节点，找到numa_id numa节点*/
        if (n->numa_id == numa_id) {
            n->n_cores++;/*numa核计数+1*/
            return;
        }
    }

    /*没找到numa节点，重新申请*/
    n = xzalloc(sizeof *n);
    n->numa_id = numa_id;
    n->n_cores = 1;

    /*numa节点插入dump，dump记录所有numa节点*/
    hmap_insert(&dump->numas, &n->hmap_node, hash_int(numa_id, 0));
}

/* Given the 'numa_id', returns dump of all cores on the numa node. */
struct ovs_numa_dump *
ovs_numa_dump_cores_on_numa(int numa_id)
{
    struct ovs_numa_dump *dump = ovs_numa_dump_create();
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        struct cpu_core *core;

        LIST_FOR_EACH (core, list_node, &numa->cores) {
            ovs_numa_dump_add(dump, numa->numa_id, core->core_id);
        }
    }

    return dump;
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_cores_with_cmask
 功能描述  :    置位掩码CPU id填入所属numa，numa节点在dump
 输入参数  :  	cmask---numa掩码字符串指针
 输出参数  :	
 返 回 值  : 	dump---根据掩码获取置位的CPU核id

 这一个函数核心思想见wiki或者STFW:[keywords:cpu亲和性配置]
 http://10.10.3.15:8090/pages/viewpage.action?pageId=7909055
*******************************************************************************/
struct ovs_numa_dump *
ovs_numa_dump_cores_with_cmask(const char *cmask)
{
    /*记录numa 核id*/
    struct ovs_numa_dump *dump = ovs_numa_dump_create();
    int core_id = 0;
    int end_idx;

    /* Ignore leading 0x. */
    end_idx = 0;
    /*掩码*/
    if (!strncmp(cmask, "0x", 2) || !strncmp(cmask, "0X", 2)) {
        end_idx = 2;
    }

    for (int i = strlen(cmask) - 1; i >= end_idx; i--) {
        char hex = cmask[i];
        int bin;

        bin = hexit_value(hex);
        if (bin == -1) {
            VLOG_WARN("Invalid cpu mask: %c", cmask[i]);
            bin = 0;
        }

        for (int j = 0; j < 4; j++) {
            if ((bin >> j) & 0x1) {
                struct cpu_core *core = get_core_by_core_id(core_id);

                if (core) {
                    ovs_numa_dump_add(dump,
                                      core->numa->numa_id,
                                      core->core_id);
                }
            }

            core_id++;
        }
    }

    return dump;
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_n_cores_per_numa
 功能描述  :    遍历all_numa_nodes上所有numa节点，numa节点上的cores_per_numa个CPU核id填入dump
 输入参数  :  	cores_per_numa---每个numa上要记录入dump的核数
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
struct ovs_numa_dump *
ovs_numa_dump_n_cores_per_numa(int cores_per_numa)
{
    /*申请一个numa dump 结构，用来描述numa*/
    struct ovs_numa_dump *dump = ovs_numa_dump_create();
    const struct numa_node *n;

    /*遍历all_numa_nodes上所有numa节点，使用hmap管理*/
    HMAP_FOR_EACH (n, hmap_node, &all_numa_nodes) {
        const struct cpu_core *core;
        int i = 0;

       /*遍历numa 上 的核信息，填入dump信息 numa */
        LIST_FOR_EACH (core, list_node, &n->cores) {
            if (i++ >= cores_per_numa) {
                break;
            }

            /*逻辑核id填入numa节点，numa节点若为新增填入dump，numa管理图*/
            ovs_numa_dump_add(dump, core->numa->numa_id, core->core_id);
        }
    }

    return dump;
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_contains_core
 功能描述  :    查询numa_id与core_id 在dump 结构是否存在
 输入参数  :  	dump---掩码后CPU核
 			    numa_id---numa id
 			    core_id---逻辑核id
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
bool
ovs_numa_dump_contains_core(const struct ovs_numa_dump *dump,
                            int numa_id, unsigned core_id)
{
    struct ovs_numa_info_core *core;

    HMAP_FOR_EACH_WITH_HASH (core, hmap_node, hash_2words(numa_id, core_id),
                             &dump->cores) {
        if (core->core_id == core_id && core->numa_id == numa_id) {
            return true;
        }
    }

    return false;
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_count
 功能描述  :    
 输入参数  :    
 输出参数  :    
 返 回 值  :     无
*******************************************************************************/
size_t
ovs_numa_dump_count(const struct ovs_numa_dump *dump)
{
    return hmap_count(&dump->cores);
}

/*******************************************************************************
 函数名称  :    ovs_numa_dump_destroy
 功能描述  :    destroy掉dump numa 与核 结构
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
void
ovs_numa_dump_destroy(struct ovs_numa_dump *dump)
{
    struct ovs_numa_info_core *c;
    struct ovs_numa_info_numa *n;

    if (!dump) {
        return;
    }

    /*释放dump上的core 节点*/
    HMAP_FOR_EACH_POP (c, hmap_node, &dump->cores) {
        free(c);
    }

    /*释放dump上的numa节点*/
    HMAP_FOR_EACH_POP (n, hmap_node, &dump->numas) {
        free(n);
    }

    /*清除core结构*/
    hmap_destroy(&dump->cores);
    /*清除numa结构*/
    hmap_destroy(&dump->numas);

    free(dump);
}

/*******************************************************************************
 函数名称  :    ovs_numa_thread_setaffinity_core
 功能描述  :    线程numa亲和性设置,设置pmd亲和的逻辑核id
 输入参数  :    core_id---逻辑核ID
 输出参数  :	
 返 回 值  : 	无
 具体分析见wiki:http://10.10.3.15:8090/pages/viewpage.action?pageId=7909055
*******************************************************************************/
struct ovs_numa_dump *
ovs_numa_thread_getaffinity_dump(void)
{
    if (dummy_numa) {
        /* Nothing to do. */
        return NULL;
    }

#ifndef __linux__
    return NULL;
#else
    struct ovs_numa_dump *dump;
    const struct numa_node *n;
    cpu_set_t cpuset;
    int err;

    CPU_ZERO(&cpuset);
    err = pthread_getaffinity_np(pthread_self(), sizeof cpuset, &cpuset);
    if (err) {
        VLOG_ERR("Thread getaffinity error: %s", ovs_strerror(err));
        return NULL;
    }

    dump = ovs_numa_dump_create();

    HMAP_FOR_EACH (n, hmap_node, &all_numa_nodes) {
        const struct cpu_core *core;

        LIST_FOR_EACH (core, list_node, &n->cores) {
            if (CPU_ISSET(core->core_id, &cpuset)) {
                ovs_numa_dump_add(dump, core->numa->numa_id, core->core_id);
            }
        }
    }

    if (!ovs_numa_dump_count(dump)) {
        ovs_numa_dump_destroy(dump);
        return NULL;
    }
    return dump;
#endif /* __linux__ */
}

int
ovs_numa_thread_setaffinity_dump(const struct ovs_numa_dump *dump)
{
    if (!dump || dummy_numa) {
        /* Nothing to do. */
        return 0;
    }

#ifdef __linux__
    const struct ovs_numa_info_core *core;
    cpu_set_t cpuset;
    int err;

    CPU_ZERO(&cpuset);
    FOR_EACH_CORE_ON_DUMP (core, dump) {
        CPU_SET(core->core_id, &cpuset);
    }
    err = pthread_setaffinity_np(pthread_self(), sizeof cpuset, &cpuset);
    if (err) {
        VLOG_ERR("Thread setaffinity error: %s", ovs_strerror(err));
        return err;
    }

    return 0;
#else /* !__linux__ */
    return EOPNOTSUPP;
#endif /* __linux__ */
}

int ovs_numa_thread_setaffinity_core(unsigned core_id)
{
    const struct cpu_core *core = get_core_by_core_id(core_id);
    struct ovs_numa_dump *affinity = ovs_numa_dump_create();
    int ret = EINVAL;

    if (core) {
        ovs_numa_dump_add(affinity, core->numa->numa_id, core->core_id);
        ret = ovs_numa_thread_setaffinity_dump(affinity);
    }

    ovs_numa_dump_destroy(affinity);
    return ret;
}
