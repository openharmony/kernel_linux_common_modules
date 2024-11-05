/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 */

#include <linux/proc_fs.h>

#include "dsmm_secureshield.h"
#include "xpm_log.h"

#define STATE_UNINT 0
#define STATE_ON    1
#define STATE_OFF   2

static uint32_t secureshield_state = STATE_UNINT;
static int init_secureshield_state(void)
{
    if (strstr(saved_command_line, "advsecmode.state=1")) {
        secureshield_state = STATE_ON;
    } else {
        // secureshield is defaultly set to off
        secureshield_state = STATE_OFF;
    }
    xpm_log_info("secureshield init to %d", secureshield_state);
    return secureshield_state;
}

static int get_secureshield_state(void)
{
    if (secureshield_state == STATE_UNINT) {
        return init_secureshield_state();
    } else {
        return secureshield_state;
    }
}

bool dsmm_is_secureshield_enabled(void)
{
    return get_secureshield_state() == STATE_ON;
}