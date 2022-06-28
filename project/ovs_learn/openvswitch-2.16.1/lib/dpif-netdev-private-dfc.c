/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 * Copyright (c) 2019, 2020, 2021 Intel Corporation.
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

#include "dpif-netdev-private-dfc.h"

static void
emc_clear_entry(struct emc_entry *ce)
{
    if (ce->flow) {
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}

static void
smc_clear_entry(struct smc_bucket *b, int idx)
{
    b->flow_idx[idx] = UINT16_MAX;
}

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len = sizeof(struct miniflow);
        flowmap_init(&flow_cache->entries[i].key.mf.map);
    }
}

/*******************************************************************************
 函数名称  :    smc_cache_init
 功能描述  :    smc bucket初始化
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
static void
smc_cache_init(struct smc_cache *smc_cache)
{
    int i, j;
        /*smc 桶与桶深初始化，桶=1u << 20 /4 = 1048576*/
    for (i = 0; i < SMC_BUCKET_CNT; i++) {
            /*桶深是4*/
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_cache->buckets[i].flow_idx[j] = UINT16_MAX;
        }
    }
}

/*******************************************************************************
 函数名称  :    dfc_cache_init
 功能描述  :    emc缓存、smc缓存初始化
 输入参数  :  	
 输出参数  :	
 返 回 值  : 	无
*******************************************************************************/
void
dfc_cache_init(struct dfc_cache *flow_cache)
{
    emc_cache_init(&flow_cache->emc_cache);
    smc_cache_init(&flow_cache->smc_cache);
}

static void
emc_cache_uninit(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        emc_clear_entry(&flow_cache->entries[i]);
    }
}

static void
smc_cache_uninit(struct smc_cache *smc)
{
    int i, j;

    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_clear_entry(&(smc->buckets[i]), j);
        }
    }
}

void
dfc_cache_uninit(struct dfc_cache *flow_cache)
{
    smc_cache_uninit(&flow_cache->smc_cache);
    emc_cache_uninit(&flow_cache->emc_cache);
}

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
    
/*******************************************************************************
 函数名称  :    emc_cache_slow_sweep
 功能描述  :    emc流表删除
 输入参数  :    
 输出参数  :    
 返 回 值  :     无
*******************************************************************************/
void
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
    /*8192个entry中获取新的entry*/
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

    /*emc流表存在 且 活着*/
    if (!emc_entry_alive(entry)) {
        /*emc流表删除*/
        emc_clear_entry(entry);
    }

    /*8192个entry hash出一个 作为老化entry index*/
    flow_cache->sweep_idx = (flow_cache->sweep_idx + 1) & EM_FLOW_HASH_MASK;
}
