#if !defined(wf80211_API_H)
#define wf80211_API_H
#include <linux/nl80211.h>
#include <netlink/socket.h>

#define DATA_STR "AP_DATA: "
#define DEFAULT_IFNAME "wlp0s20f3"

typedef struct
{
    struct nl_sock* sk;
    struct nl_cb* finish_cb;
    struct nl_cb* start_scan_cb;
    struct nl_cb* get_scan_cb;
    struct nl_cb* ack_cb;
    struct nl_cb* err_cb;
    int id_family;
    int if_index;
} netlink_t;

struct scan_results
{
    int done;
    int aborted;
};

int start_scan_wfaps(netlink_t* nl);
int init_sk(netlink_t* nl);
int get_scan_results(netlink_t* nl);

struct print_ies_data
{
    unsigned char* ie;
    int ielen;
};

struct ie_print
{
    const char* name;
    void (*print)(const uint8_t type, uint8_t len, const uint8_t* data,
                  const struct print_ies_data* ie_buffer);
    uint8_t minlen, maxlen;
};

#endif
