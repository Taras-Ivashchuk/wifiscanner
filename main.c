#include "wf80211_api.h"
#include <net/if.h>
#include <string.h>

int main(int argc, char** argv)
{
    netlink_t nl = {.sk = NULL,
                    .ack_cb = NULL,
                    .finish_cb = NULL,
                    .id_family = 0,
                    .if_index = 0};

    char* ifname = DEFAULT_IFNAME;
    if (argc > 1)
    {
        ifname = argv[1];
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex)
    {
        printf("err if_nametoindex %s\n", strerror(ifindex));
        return -1;
    }

    nl.if_index = ifindex;

    if (init_sk(&nl) < 0)
    {
        printf("err init_sk()\n");
        return -1;
    }

    if (start_scan_wfaps(&nl) < 0)
    {
        printf("err scan_wfaps\n");
        nl_socket_free(nl.sk);
        return -1;
    }

    if (get_scan_results(&nl) < 0)
    {
        printf("err get_scan_results\n");
        nl_socket_free(nl.sk);
        return -1;
    }

    nl_socket_free(nl.sk);
    return 0;
}
