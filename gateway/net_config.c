#include "net_config.h"
#include "multihoming.h"   /* PRIMARY_IP / SECONDARY_IP loopback defaults */

#include <stdlib.h>

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && *v) ? v : fallback;
}

const char *gw_local_primary(void)   { return env_or("GW_LOCAL_PRIMARY",   PRIMARY_IP);   }
const char *gw_local_secondary(void) { return env_or("GW_LOCAL_SECONDARY", SECONDARY_IP); }
const char *gw_peer_primary(void)    { return env_or("GW_PEER_PRIMARY",    PRIMARY_IP);   }
const char *gw_peer_secondary(void)  { return env_or("GW_PEER_SECONDARY",  SECONDARY_IP); }

int gw_sctp_port(void)
{
    const char *v = getenv("GW_SCTP_PORT");
    int p = v ? atoi(v) : 0;
    return p > 0 ? p : 5000;
}
