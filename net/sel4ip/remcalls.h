#ifndef _H_REMCALLS_H
#define _H_REMCALLS_H

#define MINLOCK

#define REM_BUFFSIZE 3072

typedef struct rem_pico_socket rem_pico_socket_t;

extern int rem_init(void (*eventfunc)(uint16_t ev, void *s, void *priv));

extern void rem_deinit(void);

extern iprcchan_t *rem_get_chan(int nr);

extern void rem_stack_lock(iprcchan_t *chan);

extern void rem_stack_unlock(iprcchan_t *chan);

extern void rem_set_priv(iprcchan_t *chan, rem_pico_socket_t *s, void *priv);

typedef struct rem_set_priv_arg {
	rem_pico_socket_t *s;
	void              *priv;
} rem_set_priv_arg_t;

/* ioctl helpers */
/* DO NOT CALL WITH LOCK */

#define MAX_DEVICES 10
#define MAX_ROUTES	10

typedef char pico_dev_name_t[MAX_DEVICE_NAME];

typedef struct pico_devices {
	int             count;
	pico_dev_name_t names[MAX_DEVICES];
} pico_devices_t;

typedef struct pico_device_config {
	pico_dev_name_t    name;
	int                hasipv4link;
	union pico_address address;
	union pico_address netmask;
	uint32_t           mtu;
	int                hasmac;
	struct pico_eth    mac;
} pico_device_config_t;

typedef struct pico_route {
	pico_dev_name_t    devname;
	union pico_address dest;
	union pico_address netmask;
	union pico_address gateway;
	int                metric;
	int                flags;
} pico_route_t;

typedef struct pico_routes {
	int          count;
	pico_route_t routes[MAX_ROUTES];
} pico_routes_t;

extern int rem_get_devices(iprcchan_t *chan, pico_devices_t *devices);

typedef struct rem_get_devices_res {
	int            retval;
	pico_devices_t devices;
} rem_get_devices_res_t;

extern int rem_get_device_config(iprcchan_t *chan, const char *name, pico_device_config_t *conf);

typedef struct rem_get_device_config_arg {
	pico_dev_name_t name;
} rem_get_device_config_arg_t;

typedef struct rem_get_device_config_res {
	int                  retval;
	pico_device_config_t config;
} rem_get_device_config_res_t;

extern int rem_set_device_address(iprcchan_t *chan, const char *name, union pico_address *address, union pico_address *netmask);

typedef struct rem_set_device_address_arg {
	pico_dev_name_t    name;
	union pico_address address;
	union pico_address netmask;
} rem_set_device_address_arg_t;

typedef struct rem_set_device_address_res {
	int retval;
} rem_set_device_address_res_t;

extern int rem_device_down(iprcchan_t *chan, const char *name);

typedef struct rem_device_down_arg {
	pico_dev_name_t    name;
} rem_device_down_arg_t;

typedef struct rem_device_down_res {
	int retval;
} rem_device_down_res_t;

extern int rem_device_addroute(iprcchan_t         *chan,
							   const char         *name,
		                       union pico_address *address,
							   union pico_address *genmask,
							   union pico_address *gateway,
							   int                 metric);

typedef struct rem_device_addroute_arg {
	pico_dev_name_t    name;
	union pico_address address;
	union pico_address genmask;
	union pico_address gateway;
	int                metric;
} rem_device_addroute_arg_t;

typedef struct rem_device_addroute_res {
	int retval;
} rem_device_addroute_res_t;

extern int rem_get_routes(iprcchan_t *chan, pico_routes_t *routes);

typedef struct rem_get_routes_res {
	int           retval;
	pico_routes_t routes;
} rem_get_routes_res_t;

/* socket functions */
/* YOU MUST LOCK */

extern int rem_pico_socket_shutdown(iprcchan_t *chan, rem_pico_socket_t *s, int mode);

typedef struct rem_pico_socket_shutdown_arg {
	rem_pico_socket_t *s;
	int                mode;
} rem_pico_socket_shutdown_arg_t;

typedef struct rem_pico_socket_shutdown_res {
	int retval;
} rem_pico_socket_shutdown_res_t;

extern int rem_pico_socket_connect(iprcchan_t *chan, rem_pico_socket_t *s, const union pico_address *srv_addr, uint16_t remote_port);

typedef struct rem_pico_socket_connect_arg {
	rem_pico_socket_t  *s;
	union pico_address  srv_addr;
	uint16_t            remote_port;
} rem_pico_socket_connect_arg_t;

typedef struct rem_pico_socket_connect_res {
	int retval;
} rem_pico_socket_connect_res_t;

extern int rem_pico_socket_close(iprcchan_t *chan, rem_pico_socket_t *s);

typedef struct rem_pico_socket_close_arg {
	rem_pico_socket_t *s;
} rem_pico_socket_close_arg_t;

typedef struct rem_pico_socket_close_res {
	int retval;
} rem_pico_socket_close_res_t;

extern int rem_pico_socket_bind(iprcchan_t *chan, rem_pico_socket_t *s, union pico_address *local_addr, uint16_t *port);

typedef struct rem_pico_socket_bind_arg {
	rem_pico_socket_t  *s;
	union pico_address  local_addr;
	uint16_t            port;
} rem_pico_socket_bind_arg_t;

typedef struct rem_pico_socket_bind_res {
	int      retval;
	uint16_t port;
} rem_pico_socket_bind_res_t;

extern int rem_pico_socket_getname(iprcchan_t *chan, rem_pico_socket_t *s, union pico_address *local_addr, uint16_t *port, uint16_t *proto, int peer);

typedef struct rem_pico_socket_getname_arg {
	rem_pico_socket_t  *s;
	int                 peer;
} rem_pico_socket_getname_arg_t;

typedef struct rem_pico_socket_getname_res {
	int                retval;
	union pico_address local_addr;
	uint16_t           port;
	uint16_t           proto;
} rem_pico_socket_getname_res_t;

extern rem_pico_socket_t *rem_pico_socket_accept(iprcchan_t *chan, rem_pico_socket_t *s, union pico_address *orig, uint16_t *port);

typedef struct rem_pico_socket_accept_arg {
	rem_pico_socket_t  *s;
} rem_pico_socket_accept_arg_t;

typedef struct rem_pico_socket_accept_res {
	rem_pico_socket_t  *retval;
	union pico_address  orig;
	uint16_t            port;
} rem_pico_socket_accept_res_t;

extern int rem_pico_socket_listen(iprcchan_t *chan, rem_pico_socket_t *s, const int backlog);

typedef struct rem_pico_socket_listen_arg {
	rem_pico_socket_t *s;
	int                backlog;
} rem_pico_socket_listen_arg_t;

typedef struct rem_pico_socket_listen_res {
	int retval;
} rem_pico_socket_listen_res_t;

extern int rem_pico_socket_sendto(iprcchan_t *chan, rem_pico_socket_t *s, const void *buf, int len, union pico_address *dst, uint16_t remote_port);

typedef struct rem_pico_socket_sendto_arg {
	rem_pico_socket_t  *s;
	int                 len;
	union pico_address  dst;
	uint16_t            remote_port;
	char                buf[1];
} rem_pico_socket_sendto_arg_t;

typedef struct rem_pico_socket_sendto_res {
	int retval;
} rem_pico_socket_sendto_res_t;

struct msghdr;

extern int rem_pico_socket_sendto_msg(iprcchan_t *chan, rem_pico_socket_t *s, struct msghdr *msg, int len, union pico_address *dst, uint16_t remote_port);

extern int rem_pico_socket_send(iprcchan_t *chan, rem_pico_socket_t *s, const void *buf, int len);

typedef struct rem_pico_socket_send_arg {
	rem_pico_socket_t  *s;
	int                 len;
	char                buf[1];
} rem_pico_socket_send_arg_t;

typedef struct rem_pico_socket_send_res {
	int retval;
} rem_pico_socket_send_res_t;

extern int rem_pico_socket_send_msg(iprcchan_t *chan, rem_pico_socket_t *s, struct msghdr *msg, int len);

extern int rem_pico_socket_recvfrom(iprcchan_t *chan, rem_pico_socket_t *s, void *buf, int len, union pico_address *orig, uint16_t *local_port);

typedef struct rem_pico_socket_recvfrom_arg {
	rem_pico_socket_t *s;
	int                len;
} rem_pico_socket_recvfrom_arg_t;

typedef struct rem_pico_socket_recvfrom_res {
	int                retval;
	union pico_address orig;
	uint16_t           local_port;
	char               buf[1];
} rem_pico_socket_recvfrom_res_t;

extern int rem_pico_socket_recvfrom_msg(iprcchan_t *chan, rem_pico_socket_t *s, struct msghdr *msg, int len, union pico_address *orig, uint16_t *local_port);

extern int rem_pico_socket_udp_poll(iprcchan_t *chan, rem_pico_socket_t *s);

typedef struct rem_pico_socket_udp_poll_arg {
	rem_pico_socket_t *s;
} rem_pico_socket_udp_poll_arg_t;

typedef struct rem_pico_socket_udp_poll_res {
	int                retval;
} rem_pico_socket_udp_poll_res_t;

extern rem_pico_socket_t *rem_pico_socket_open(iprcchan_t *chan, uint16_t net, uint16_t proto);

typedef struct rem_pico_socket_open_arg {
	uint16_t   net;
	uint16_t   proto;
} rem_pico_socket_open_arg_t;

typedef struct rem_pico_socket_open_res {
	rem_pico_socket_t *retval;
} rem_pico_socket_open_res_t;

extern int rem_pico_socket_getoption(iprcchan_t *chan, rem_pico_socket_t *s, int option, void *value, int *optlen);

typedef struct rem_pico_socket_getoption_arg {
	rem_pico_socket_t *s;
	int                option;
	int                optlen;
} rem_pico_socket_getoption_arg_t;

typedef struct rem_pico_socket_getoption_res {
	int                retval;
	int                optlen;
	char               value[1];
} rem_pico_socket_getoption_res_t;

extern int rem_pico_socket_setoption(iprcchan_t *chan, rem_pico_socket_t *s, int option, void *value, int optlen);

typedef struct rem_pico_socket_setoption_arg {
	rem_pico_socket_t *s;
	int                option;
	int                optlen;
	char               value[1];
} rem_pico_socket_setoption_arg_t;

typedef struct rem_pico_socket_setoption_res {
	int                retval;
} rem_pico_socket_setoption_res_t;

// remote functions structs

typedef enum rem_functions {
	f_rem_stack_lock,
	f_rem_stack_unlock,
	f_rem_set_priv,
	f_rem_get_devices,
	f_rem_get_device_config,
	f_rem_set_device_address,
	f_rem_device_down,
	f_rem_device_addroute,
	f_rem_get_routes,
	f_rem_pico_socket_shutdown,
	f_rem_pico_socket_connect,
	f_rem_pico_socket_close,
	f_rem_pico_socket_bind,
	f_rem_pico_socket_getname,
	f_rem_pico_socket_accept,
	f_rem_pico_socket_listen,
	f_rem_pico_socket_sendto,
	f_rem_pico_socket_send,
	f_rem_pico_socket_recvfrom,
	f_rem_pico_socket_udp_poll,
	f_rem_pico_socket_open,
	f_rem_pico_socket_getoption,
	f_rem_pico_socket_setoption,
	rem_functions_max
} rem_functions_t;

typedef struct rem_arg_hdr {
	rem_functions_t func;
} rem_arg_hdr_t;

typedef struct rem_res_hdr {
	pico_err_t pico_err;
} rem_res_hdr_t;

typedef struct rem_arg {
	rem_arg_hdr_t hdr;
	union {
		rem_set_priv_arg_t              rem_set_priv_arg;
		rem_get_device_config_arg_t     rem_get_device_config_arg;
		rem_set_device_address_arg_t    rem_set_device_address_arg;
		rem_device_down_arg_t           rem_device_down_arg;
		rem_device_addroute_arg_t       rem_device_addroute_arg;
		rem_pico_socket_shutdown_arg_t  rem_pico_socket_shutdown_arg;
		rem_pico_socket_connect_arg_t   rem_pico_socket_connect_arg;
		rem_pico_socket_close_arg_t     rem_pico_socket_close_arg;
		rem_pico_socket_bind_arg_t      rem_pico_socket_bind_arg;
		rem_pico_socket_getname_arg_t   rem_pico_socket_getname_arg;
		rem_pico_socket_accept_arg_t    rem_pico_socket_accept_arg;
		rem_pico_socket_listen_arg_t    rem_pico_socket_listen_arg;
		rem_pico_socket_sendto_arg_t    rem_pico_socket_sendto_arg;
		rem_pico_socket_send_arg_t      rem_pico_socket_send_arg;
		rem_pico_socket_recvfrom_arg_t  rem_pico_socket_recvfrom_arg;
		rem_pico_socket_udp_poll_arg_t  rem_pico_socket_udp_poll_arg;
		rem_pico_socket_open_arg_t      rem_pico_socket_open_arg;
		rem_pico_socket_getoption_arg_t rem_pico_socket_getoption_arg;
		rem_pico_socket_setoption_arg_t rem_pico_socket_setoption_arg;
	} u;
} rem_arg_t;

typedef struct rem_res {
	rem_res_hdr_t hdr;
	union {
		rem_get_devices_res_t           rem_get_devices_res;
		rem_get_device_config_res_t     rem_get_device_config_res;
		rem_set_device_address_res_t    rem_set_device_address_res;
		rem_device_down_res_t           rem_device_down_res;
		rem_device_addroute_res_t       rem_device_addroute_res;
		rem_get_routes_res_t            rem_get_routes_res;
		rem_pico_socket_shutdown_res_t  rem_pico_socket_shutdown_res;
		rem_pico_socket_connect_res_t   rem_pico_socket_connect_res;
		rem_pico_socket_close_res_t     rem_pico_socket_close_res;
		rem_pico_socket_bind_res_t      rem_pico_socket_bind_res;
		rem_pico_socket_getname_res_t   rem_pico_socket_getname_res;
		rem_pico_socket_accept_res_t    rem_pico_socket_accept_res;
		rem_pico_socket_listen_res_t    rem_pico_socket_listen_res;
		rem_pico_socket_sendto_res_t    rem_pico_socket_sendto_res;
		rem_pico_socket_send_res_t      rem_pico_socket_send_res;
		rem_pico_socket_recvfrom_res_t  rem_pico_socket_recvfrom_res;
		rem_pico_socket_udp_poll_res_t  rem_pico_socket_udp_poll_res;
		rem_pico_socket_open_res_t      rem_pico_socket_open_res;
		rem_pico_socket_getoption_res_t rem_pico_socket_getoption_res;
		rem_pico_socket_setoption_res_t rem_pico_socket_setoption_res;
	} u;
} rem_res_t;

// calback structs

typedef enum remcb_functions {
	f_remcb_pico_socket_event,
	remcb_functions_max
} remcb_functions_t;

typedef struct remcb_arg_hdr {
	remcb_functions_t func;
} remcb_arg_hdr_t;

typedef struct remcb_pico_socket_event_arg {
	uint16_t   ev;
	void      *s;
	void      *priv;
} remcb_pico_socket_event_arg_t;

typedef struct remcb_arg {
	remcb_arg_hdr_t hdr;
	union {
		remcb_pico_socket_event_arg_t remcb_pico_socket_event_arg;
	} u;
} remcb_arg_t;

#endif
