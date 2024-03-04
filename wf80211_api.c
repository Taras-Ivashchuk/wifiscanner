#include "wf80211_api.h"
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <stdio.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

// prototypes start
int ack_handler(struct nl_msg* msg, void* arg);
int finish_handler(struct nl_msg* msg, void* arg);
int get_scan_handler(struct nl_msg* msg, void* arg);
int err_handler(struct sockaddr_nl* nla, struct nlmsgerr* err, void* arg);

int config_custom_cb(struct nl_cb* cb, enum nl_cb_type cbtype,
                     nl_recvmsg_msg_cb_t func, void* funcarg);
int config_custom_err_cb(struct nl_cb* cb, nl_recvmsg_err_cb_t func,
                         void* funcarg);
int construct_start_scan_msg(netlink_t* nl, struct nl_msg* msg);
int construct_get_scan_msg(netlink_t* nl, struct nl_msg* get_scan_msg);
int valid_msg_handler(struct nl_msg* msg, void* arg);
void mac_addr_n2a(char* mac_addr, unsigned char* arg);
void dataline();
void print_ies(unsigned char* ie, int ie_len);
void print_ssid(const uint8_t type, uint8_t len, const uint8_t* data,
                const struct print_ies_data* ie_buffer);
void print_ie(const struct ie_print* p, const uint8_t type, uint8_t len,
              const uint8_t* data, const struct print_ies_data* ie_buffer);
int frequency_to_channel(int freq);
int no_seq_check_handler(struct nl_msg* msg, void* arg);
void print_rsn(const uint8_t type, uint8_t len, const uint8_t* data,
               const struct print_ies_data* ie_buffer);
void print_rsn_ie(const char* defcipher, const char* defauth, uint8_t len,
                  const uint8_t* data);

// prototypes end

static const struct ie_print ieprinters[] = {[0] =
                                                 {
                                                     "ssid",
                                                     print_ssid,
                                                     0,
                                                     32,
                                                 },
                                             [48] = {
                                                 "rsn",
                                                 print_rsn,
                                                 2,
                                                 255,
                                             }};

static char g_current_mac[20];
static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
    [NL80211_BSS_BSSID] = {.type = NLA_UNSPEC},
    [NL80211_BSS_FREQUENCY] = {.type = NLA_U32},
    [NL80211_BSS_TSF] = {.type = NLA_U64},
    [NL80211_BSS_BEACON_INTERVAL] = {.type = NLA_U16},
    [NL80211_BSS_CAPABILITY] = {.type = NLA_U16},
    [NL80211_BSS_INFORMATION_ELEMENTS] = {.type = NLA_UNSPEC},
    [NL80211_BSS_SIGNAL_MBM] = {.type = NLA_U32},
    [NL80211_BSS_SIGNAL_UNSPEC] = {.type = NLA_U8},
    [NL80211_BSS_STATUS] = {.type = NLA_U32},
    [NL80211_BSS_SEEN_MS_AGO] = {.type = NLA_U32},
    [NL80211_BSS_BEACON_IES] = {.type = NLA_UNSPEC},
};

int init_sk(netlink_t* nl)
{
    // allocate socket
    nl->sk = (void*)nl_socket_alloc();
    if (nl->sk == NULL)
    {
        printf("err socket_alloc()\n");
        return -1;
    }

    // connect the allocated socket to libnl
    int err = genl_connect(nl->sk);
    if (err < 0)
    {
        printf("Error connecting nl socket: %d, %s\n", err, nl_geterror(err));
        goto exit;
    }

    // find the driver id for nl80211 family
    int resolved_id = 0;
    resolved_id = genl_ctrl_resolve(nl->sk, "nl80211");

    if (resolved_id < 0)
    {
        printf("\nnegative error code returned: %d, %s\n", resolved_id,
               nl_geterror(resolved_id));
        goto exit;
    }

    nl->id_family = resolved_id;

    int mcid = -1;
    mcid = genl_ctrl_resolve_grp(nl->sk, "nl80211", "scan");

    if (mcid < 0)
    {
        printf("error resolving netlink group name to identifier: %d, %s\n",
               mcid, nl_geterror(err));
        return 1;
    }

    // join the netlink socket into the scan group resolved above
    err = nl_socket_add_membership(nl->sk, mcid);
    if (err < 0)
    {
        printf("error joining scan group: %d, %s\n", err, nl_geterror(err));
        return 1;
    }

    return 0;

exit:
    nl_close(nl->sk);
    nl_socket_free(nl->sk);
    return -1;
}

int config_custom_cb(struct nl_cb* cb, enum nl_cb_type cbtype,
                     nl_recvmsg_msg_cb_t func, void* funcarg)
{
    int ret = 0;
    if ((ret = nl_cb_set(cb, cbtype, NL_CB_CUSTOM, func, funcarg)) < 0)
    {
        printf("err config_custom_cb: %d, %s\n", ret, nl_geterror(ret));
        return ret;
    }

    return 0;
}

int config_custom_err_cb(struct nl_cb* cb, nl_recvmsg_err_cb_t func,
                         void* funcarg)
{
    int ret = 0;
    if ((ret = nl_cb_err(cb, NL_CB_CUSTOM, func, funcarg)) < 0)
    {
        printf("err config_custom_err_cb: %d, %s\n", ret, nl_geterror(ret));
        return ret;
    }

    return 0;
}

int construct_start_scan_msg(netlink_t* nl, struct nl_msg* msg)
{
    int flags = 0;
    int usrhdrlen = 0;
    uint8_t ifversion = 0;
    enum nl80211_commands cmd = NL80211_CMD_TRIGGER_SCAN;

    int err = 0;
    if ((err = nl_socket_add_membership(nl->sk, nl->id_family)) < 0)
    {
        printf("error joining scan group: %d, %s\n", err, nl_geterror(err));
        return 1;
    }

    // append generic netlink header to the main message
    if (genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl->id_family, usrhdrlen,
                    flags, cmd, ifversion) == NULL)
    {
        printf("err genlmsg_put \n");
        return -1;
    }

    // append ifindex attribute to the main message

    if (nla_put_u32(msg, NL80211_ATTR_IFINDEX, nl->if_index) < 0)
    {
        printf("err nla_put_u32 attr_ifindex \n");
        return -1;
    }

    // allocate nested message which be appended to the main message
    struct nl_msg* ssids_to_scan = nlmsg_alloc();
    if (ssids_to_scan == NULL)
    {
        printf("err ssids nlmsg_alloc\n");
        return -1;
    }
    // append  wiphy attr to the nested message
    if (nla_put(ssids_to_scan, NL80211_ATTR_WIPHY, 0, "") < 0)
    {

        nlmsg_free(ssids_to_scan);
        return -1;
    }

    // append the nested message to the main message

    if (nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan) < 0)
    {
        printf("err nla_put_nested \n");
        nlmsg_free(ssids_to_scan);
        return -1;
    }

    nlmsg_free(ssids_to_scan);

    return 0;
}

int start_scan_wfaps(netlink_t* nl)

{
    int arg = -1;
    int ret = -1;

    struct scan_results results = {.done = 0, .aborted = 0};

    nl->start_scan_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (nl->start_scan_cb == NULL)
    {
        printf("err finish start scan nl_cb_alloc\n");
        return -1;
    }

    if ((ret = config_custom_cb(nl->start_scan_cb, NL_CB_VALID,
                                valid_msg_handler, &results)) < 0)
    {
        printf("err config triggen scan NL_CB_VALID: arg %d, ret %d\n", arg,
               ret);
        return -1;
    }

    if ((ret = config_custom_err_cb(nl->start_scan_cb, err_handler, &arg)) < 0)
    {
        printf("err config start scan error handler arg %d, ret %d \n", arg,
               ret);
        return -1;
    }

    int ack_got = -1;
    if ((ret = config_custom_cb(nl->start_scan_cb, NL_CB_ACK, ack_handler,
                                &ack_got)) < 0)
    {
        printf("err config start scan NL_CB_ACK: arg %d, ret %d\n", arg, ret);
        return -1;
    }

    // No sequence checking for multicast messages
    if ((ret = config_custom_cb(nl->start_scan_cb, NL_CB_SEQ_CHECK,
                                no_seq_check_handler, NULL)) < 0)
    {
        printf("Failed setting NL_CB_SEQ_CHECK callback: %d, %s\n", ret,
               nl_geterror(ret));
        return 1;
    }

    struct nl_msg* start_scan_msg = NULL;
    start_scan_msg = nlmsg_alloc();
    if (start_scan_msg == NULL)
    {
        printf("err nlmsg_alloc\n");
        return -1;
    }

    if (construct_start_scan_msg(nl, start_scan_msg) < 0)
    {
        printf("err construct_msg()\n");
        return -1;
    }

    int written = nl_send_auto(nl->sk, start_scan_msg);
    if (written < 0)
    {
        printf("err nl_send_auto_complete start scan\n");
        goto out;
    }

    // The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on success or
    // NL80211_CMD_SCAN_ABORTED if another scan was started by another process
    // use the custom cb while receiveing data from the socket TODO

    printf("scanning APs started\n");
    while (ack_got != 0)
    {
        ret = nl_recvmsgs(nl->sk, nl->start_scan_cb);
        if (ret < 0)
        {
            printf("nl_recvmsgs returned error: %d, %s\n", ret,
                   nl_geterror(ret));
            goto out;
        }
    }

    while (results.done != 1)
    {
        nl_recvmsgs(nl->sk, nl->start_scan_cb);
    }

    if (results.aborted == 1)
    {
        printf("scan was aborted\n");
        return 1;
    }

    return 0;

out:
    if (start_scan_msg != NULL)
    {
        nlmsg_free(start_scan_msg);
    }
    return -1;
}

int get_scan_handler(struct nl_msg* msg, void* arg)
{
    /* container for attributes, used for parsing nested attributes */
    struct nlattr* tb[NL80211_ATTR_MAX + 1];
    struct nlattr* bss[NL80211_BSS_MAX + 1];
    struct genlmsghdr* genhdr = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    if (genhdr == NULL)
    {
        printf("err access msg header\n");
        return NL_SKIP;
    }

    int err = nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(genhdr, 0),
                        genlmsg_attrlen(genhdr, 0), NULL);
    if (err < 0)
    {
        printf("error creating attribute indices from scan message: %d, %s\n",
               err, nl_geterror(err));
        return NL_SKIP;
    }

    if (!tb[NL80211_ATTR_BSS])
    {
        printf("bss info missing\n");
        return NL_SKIP;
    }

    // BSS information is a nested attribute type, so a second parse call is
    // needed
    err = nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS],
                           bss_policy);
    if (err < 0)
    {
        printf("failed to parse nested attributes: %d, %s\n", err,
               nl_geterror(err));
        return NL_SKIP;
    }

    if (!bss[NL80211_BSS_BSSID])
    {
        printf("no bssid in bss parsed!\n");
        return NL_SKIP;
    }

    memset(g_current_mac, '\0', sizeof(g_current_mac));
    mac_addr_n2a(g_current_mac,
                 (unsigned char*)nla_data(bss[NL80211_BSS_BSSID]));

    if (bss[NL80211_BSS_SIGNAL_MBM])
    {
        printf("\n");
        dataline();
        printf("signal strength: %d mBm\n",
               nla_get_u8(bss[NL80211_BSS_SIGNAL_MBM]));
    }

    if (bss[NL80211_BSS_FREQUENCY])
    {
        dataline();
        int freq = (int)nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        int channel = frequency_to_channel(freq);
        printf("frequency: %d MHz\n", freq);
        dataline();
        printf("channel: %d\n", channel);
    }

    if (bss[NL80211_BSS_INFORMATION_ELEMENTS])
    {
        struct nlattr* ies = bss[NL80211_BSS_INFORMATION_ELEMENTS];
        int ies_len = nla_len(ies);
        print_ies((unsigned char*)nla_data(ies), ies_len);
    }

    return NL_SKIP;
}

void print_ie(const struct ie_print* p, const uint8_t type, uint8_t len,
              const uint8_t* data, const struct print_ies_data* ie_buffer)
{
    if (!p)
    {
        return;
    }

    if (!p->print)
    {
        return;
    }

    dataline();
    printf("%s: ", p->name);
    if (len < p->minlen || len > p->maxlen)
    {

        if (len > 1)
        {
            printf(" <invalid: %d bytes:", len);
            for (int i = 0; i < len; i++)
            {
                printf(" %.02x", data[i]);
            }

            printf(">\n");
        }
        else if (len)
            printf(" <invalid: 1 byte: %.02x>\n", data[0]);
        else
            printf(" <invalid: no data>\n");
        return;
    }

    p->print(type, len, data, ie_buffer);
}

void print_ies(unsigned char* ie, int ie_len)
{
    int start = 0;
    struct print_ies_data ie_buffer = {.ie = ie, .ielen = ie_len};

    start = ie_len;
    while (start >= 2 && start - 2 >= ie[1])
    {
        if (ie[0] < ARRAY_SIZE(ieprinters))
        {
            print_ie(&ieprinters[ie[0]], ie[0], ie[1], ie + 2, &ie_buffer);
        }

        ie += ie[1] + 2;
        start -= ie[1] + 2;
    }
}

void dataline() { printf("%s%s, ", DATA_STR, g_current_mac); }

void mac_addr_n2a(char* mac_addr, unsigned char* arg)
{

    int i, l;
    l = 0;
    for (i = 0; i < 6; i++)
    {
        if (i == 0)
        {
            sprintf(mac_addr + l, "%02x", arg[i]);
            l += 2;
        }
        else
        {
            sprintf(mac_addr + l, ":%02x", arg[i]);
            l += 3;
        }
    }
}

int construct_get_scan_msg(netlink_t* nl, struct nl_msg* get_scan_msg)
{
    int hdrlen = 0;
    int flags = NLM_F_DUMP;
    uint8_t cmd = NL80211_CMD_GET_SCAN;
    uint8_t version = 0;

    if (genlmsg_put(get_scan_msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl->id_family,
                    hdrlen, flags, cmd, version) == NULL)
    {
        printf("err genlmsg_put get_scan_msg\n");
        return -1;
    }

    // Add message attribute specifying which interface to use
    nla_put_u32(get_scan_msg, NL80211_ATTR_IFINDEX, nl->if_index);

    void* funcarg = NULL;
    nl_socket_modify_cb(nl->sk, NL_CB_VALID, NL_CB_CUSTOM, get_scan_handler,
                        funcarg);

    return 0;
}

int get_scan_results(netlink_t* nl)
{

    struct nl_msg* get_scan_msg = NULL;
    get_scan_msg = nlmsg_alloc();
    if (get_scan_msg == NULL)
    {
        printf("err get scan nlmsg_alloc\n");
        return -1;
    }

    if (construct_get_scan_msg(nl, get_scan_msg) < 0)
    {
        printf("err construct get_scan_msg\n");
        return -1;
    }

    int ret = -1;
    ret = nl_send_auto(nl->sk, get_scan_msg);
    if (ret < 0)
    {
        printf("nl_send_auto() at get_scan_msg failed with: %d, %s\n", ret,
               nl_geterror(ret));
        return -1;
    }

    // wait for the message to go through
    printf("scanning APs finished: get scan results\n");
    ret = -1;
    while ((ret = nl_recvmsgs_default(nl->sk)) != 0)
    {
        printf("in a while loop: get scan results.... \n");
        if (ret < 0)
        {
            printf("ERROR: nl_recvmsgs_default() at get_scan_result failed "
                   "with "
                   "%d, %s\n",
                   ret, nl_geterror(ret));

            return -1;
        }
    }

    return 0;
}

int ack_handler(struct nl_msg* msg, void* arg)
{
    int* err = (int*)arg;
    *err = 0;
    return NL_STOP;
}

int finish_handler(struct nl_msg* msg, void* arg)
{
    int* err = (int*)arg;
    *err = 0;
    return NL_SKIP;
}

int valid_msg_handler(struct nl_msg* msg, void* arg)
{
    struct genlmsghdr* genhdr = (struct genlmsghdr*)nlmsg_data(nlmsg_hdr(msg));
    if (genhdr == NULL)
    {
        printf("err access generic msg header\n");
        return NL_SKIP;
    }

    if (genhdr->cmd == NL80211_CMD_SCAN_ABORTED)
    {
        ((struct scan_results*)arg)->aborted = 1;
        ((struct scan_results*)arg)->done = 1;
    }

    if (genhdr->cmd == NL80211_CMD_NEW_SCAN_RESULTS)
    {

        ((struct scan_results*)arg)->aborted = 0;
        ((struct scan_results*)arg)->done = 1;
    }

    return NL_SKIP;
}

int err_handler(struct sockaddr_nl* nl, struct nlmsgerr* err, void* arg)
{
    int* ret = (int*)arg;
    *ret = err->error;
    return NL_STOP;
}

void print_ssid(const uint8_t type, uint8_t len, const uint8_t* data,
                const struct print_ies_data* ie_buffer)
{
    for (int i = 0; i < len; i++)
    {
        if (isprint(data[i]) && data[i] != ' ' && data[i] != '\\')
            printf("%c", data[i]);
        else if (data[i] == ' ' && (i != 0 && i != len - 1))
            printf(" ");
        else
            printf("\\x%.2x", data[i]);
    }
    printf("\n");
}

int frequency_to_channel(int freq)
{
    if (freq < 1000)
        return 0;
    if (freq == 2484)
        return 14;
    else if (freq == 5935)
        return 2;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq < 5950)
        return (freq - 5000) / 5;
    else if (freq <= 45000)
        return (freq - 5950) / 5;
    else if (freq >= 58320 && freq <= 70200)
        return (freq - 56160) / 2160;
    else
        return 0;
}

int no_seq_check_handler(struct nl_msg* msg, void* arg)
{
    return NL_OK;
}

void print_rsn(const uint8_t type, uint8_t len, const uint8_t* data,
               const struct print_ies_data* ie_buffer)
{
    print_rsn_ie("CCMP", "IEEE 802.1X", len, data);
}

void print_rsn_ie(const char* defcipher, const char* defauth, uint8_t len,
                  const uint8_t* data)
{

    __u16 count;
    __u16 capa;
    __u16 version;

    version = data[0] + (data[1] << 8);
    printf("version:%d\n", version);

    data += 6;
    len -= 6;
    
    count = data[0] | (data[1] << 8);
    data += 2 + (count * 4);
    len -= 2 + (count * 4);
    
    count = data[0] | (data[1] << 8);
    if (2 + (count * 4) > len)
    {
        goto invalid;
    }

    data += 2 + (count * 4);
    len -= 2 + (count * 4);

    if (len >= 2)
    {
        capa = data[0] | (data[1] << 8);
        dataline();
        printf("rsn: capabilities:");
        if (capa & 0x0001)
            printf(" PreAuth");
        if (capa & 0x0002)
            printf(" NoPairwise");
        switch ((capa & 0x000c) >> 2)
        {
            case 0:
                printf(" 1-PTKSA-RC");
                break;
            case 1:
                printf(" 2-PTKSA-RC");
                break;
            case 2:
                printf(" 4-PTKSA-RC");
                break;
            case 3:
                printf(" 16-PTKSA-RC");
                break;
        }
        switch ((capa & 0x0030) >> 4)
        {
            case 0:
                printf(" 1-GTKSA-RC");
                break;
            case 1:
                printf(" 2-GTKSA-RC");
                break;
            case 2:
                printf(" 4-GTKSA-RC");
                break;
            case 3:
                printf(" 16-GTKSA-RC");
                break;
        }
        if (capa & 0x0040)
            printf(" MFP-required");
        if (capa & 0x0080)
            printf(" MFP-capable");
        if (capa & 0x0200)
            printf(" Peerkey-enabled");
        if (capa & 0x0400)
            printf(" SPP-AMSDU-capable");
        if (capa & 0x0800)
            printf(" SPP-AMSDU-required");
        if (capa & 0x2000)
            printf(" Extended-Key-ID");
        printf(" (0x%.4x)", capa);
        printf("\n");
    }
    
    return;

invalid:
    if (len != 0)
    {
        dataline();
        printf("bogus tail data:%d", len);
        while (len)
        {
            printf(" %.2x", *data);
            data++;
            len--;
        }
        printf("\n");
    }
}
