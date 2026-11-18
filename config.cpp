#include "config.h"
#include "deadzone.h"
#include "log.h"

static PadConfig g_config;

PadConfig& Config()
{
    return g_config;
}

bool Config_Apply()
{
    if (!Deadzone_Set(g_config.deadzone))
        return false;

    Log("[Config] deadzone applied = %f\n", g_config.deadzone);

    return true;
}