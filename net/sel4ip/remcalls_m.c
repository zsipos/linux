#include "picotcp.h"
#include "iprcchan.h"
#include "remcalls.h"

volatile pico_err_t pico_err;

static iprcchan_t *chan0 = NULL;
static iprcchan_t *chan1 = NULL;

static void handle_remcb_pico_socket_event(void *cb_data, remcb_arg_t *arg)
{
	remcb_pico_socket_event_arg_t *a = &arg->u.remcb_pico_socket_event_arg;
	void (*eventfunc)(uint16_t ev, void *s, void *priv) = cb_data;

	pico_err = a->err;

	eventfunc(a->ev, a->s, a->priv);
}

static void iprcchan_callback(void *cb_data, void *buffer)
{
	remcb_arg_t *arg = buffer;

	switch(arg->hdr.func) {
	case f_remcb_pico_socket_event:
		handle_remcb_pico_socket_event(cb_data, arg);
		break;
	default:
		printk("unknown remcb function %d\n", arg->hdr.func);
		break;
	}
}

static void do_call(iprcchan_t *chan)
{
	int rc = iprcchan_do_call(chan);
	if (rc)
		panic("iprc call failed!\n");
}

int rem_init(void (*eventfunc)(uint16_t ev, void *s, void *priv))
{
	chan0 = iprcchan_open(0, iprcchan_callback, eventfunc);
	if (!chan0)
		return -ENOMEM;
	chan1 = iprcchan_open(1, iprcchan_callback, eventfunc);
	if (!chan1) {
		iprcchan_close(chan0);
		chan0 = NULL;
		return -ENOMEM;
	}
	return 0;
}

void rem_deinit(void)
{
	if (chan0) {
		iprcchan_close(chan0);
		chan0 = NULL;
	}
	if (chan1) {
		iprcchan_close(chan1);
		chan1 = NULL;
	}
}

iprcchan_t *rem_get_chan(int nr)
{
	switch(nr) {
	case 0:
		return chan0;
	case 1:
		return chan1;
	default:
		return NULL;
	}
}
void rem_stack_lock(iprcchan_t *chan)
{
	rem_arg_t *arg;

	arg = iprcchan_begin_call(chan);
	arg->hdr.func = f_rem_stack_lock;
	do_call(chan);
	iprcchan_end_call(chan);
}

void rem_stack_unlock(iprcchan_t *chan)
{
	rem_arg_t *arg;

	arg = iprcchan_begin_call(chan);
	arg->hdr.func = f_rem_stack_unlock;
	do_call(chan);
	iprcchan_end_call(chan);
}

void rem_set_priv(iprcchan_t *chan, rem_pico_socket_t *s, void *priv)
{
	rem_arg_t          *arg = iprcchan_begin_call(chan);
	rem_set_priv_arg_t *a = &arg->u.rem_set_priv_arg;

	arg->hdr.func = f_rem_set_priv;
	a->s          = s;
	a->priv       = priv;
	do_call(chan);
	iprcchan_end_call(chan);
}

int rem_get_devices(iprcchan_t *chan, pico_devices_t *devices)
{
	rem_arg_t             *arg = iprcchan_begin_call(chan);
	rem_res_t             *res = (rem_res_t*)arg;
	rem_get_devices_res_t *r = &res->u.rem_get_devices_res;
	int                    retval;

	arg->hdr.func = f_rem_get_devices;
	do_call(chan);
	retval   = r->retval;
	*devices = r->devices;
	iprcchan_end_call(chan);
	return retval;
}

int rem_get_device_config(iprcchan_t *chan, const char *name, pico_device_config_t *config)
{
	rem_arg_t                   *arg = iprcchan_begin_call(chan);
	rem_res_t                   *res = (rem_res_t*)arg;
	rem_get_device_config_arg_t *a = &arg->u.rem_get_device_config_arg;
	rem_get_device_config_res_t *r = &res->u.rem_get_device_config_res;
	int                          retval;

	arg->hdr.func = f_rem_get_device_config;
	strncpy(a->name, name, sizeof(a->name)-1);
	a->name[sizeof(a->name)-1] = 0;
	do_call(chan);
	retval  = r->retval;
	*config = r->config;
	iprcchan_end_call(chan);
	return retval;
}

int rem_set_device_address(iprcchan_t *chan, const char *name, union pico_address *address, union pico_address *netmask)
{
	rem_arg_t                    *arg = iprcchan_begin_call(chan);
	rem_res_t                    *res = (rem_res_t*)arg;
	rem_set_device_address_arg_t *a = &arg->u.rem_set_device_address_arg;
	rem_set_device_address_res_t *r = &res->u.rem_set_device_address_res;
	int                           retval;

	arg->hdr.func = f_rem_set_device_address;
	strncpy(a->name, name, sizeof(a->name)-1);
	a->name[sizeof(a->name)-1] = 0;
	a->address = *address;
	a->netmask = *netmask;
	do_call(chan);
	retval = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_device_down(iprcchan_t *chan, const char *name)
{
	rem_arg_t             *arg = iprcchan_begin_call(chan);
	rem_res_t             *res = (rem_res_t*)arg;
	rem_device_down_arg_t *a = &arg->u.rem_device_down_arg;
	rem_device_down_res_t *r = &res->u.rem_device_down_res;
	int                    retval;

	arg->hdr.func = f_rem_device_down;
	strncpy(a->name, name, sizeof(a->name)-1);
	a->name[sizeof(a->name)-1] = 0;
	do_call(chan);
	retval = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_device_addroute(iprcchan_t         *chan,
		                const char         *name,
						union pico_address *address,
						union pico_address *genmask,
						union pico_address *gateway,
						int                 metric)
{
	rem_arg_t                 *arg = iprcchan_begin_call(chan);
	rem_res_t                 *res = (rem_res_t*)arg;
	rem_device_addroute_arg_t *a = &arg->u.rem_device_addroute_arg;
	rem_device_addroute_res_t *r = &res->u.rem_device_addroute_res;
	int                        retval;

	arg->hdr.func = f_rem_device_addroute;
	strncpy(a->name, name, sizeof(a->name)-1);
	a->name[sizeof(a->name)-1] = 0;
	a->address = *address;
	a->genmask = *genmask;
	a->gateway = *gateway;
	a->metric  = metric;
	do_call(chan);
	retval = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_get_routes(iprcchan_t *chan, pico_routes_t *routes)
{
	rem_arg_t            *arg = iprcchan_begin_call(chan);
	rem_res_t            *res = (rem_res_t*)arg;
	rem_get_routes_res_t *r = &res->u.rem_get_routes_res;
	int                   retval;

	arg->hdr.func = f_rem_get_routes;
	do_call(chan);
	retval  = r->retval;
	*routes = r->routes;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_shutdown(iprcchan_t *chan, rem_pico_socket_t *s, int mode)
{
	rem_arg_t                      *arg = iprcchan_begin_call(chan);
	rem_res_t                      *res = (rem_res_t*)arg;
	rem_pico_socket_shutdown_arg_t *a = &arg->u.rem_pico_socket_shutdown_arg;
	rem_pico_socket_shutdown_res_t *r = &res->u.rem_pico_socket_shutdown_res;
	int                             retval;

	arg->hdr.func = f_rem_pico_socket_shutdown;
	a->s          = s;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_connect(iprcchan_t *chan, rem_pico_socket_t *s, const union pico_address *srv_addr, uint16_t remote_port)
{
	rem_arg_t                     *arg = iprcchan_begin_call(chan);
	rem_res_t                     *res = (rem_res_t*)arg;
	rem_pico_socket_connect_arg_t *a = &arg->u.rem_pico_socket_connect_arg;
	rem_pico_socket_connect_res_t *r = &res->u.rem_pico_socket_connect_res;
	int                            retval;

	arg->hdr.func  = f_rem_pico_socket_connect;
	a->s           = s;
	a->srv_addr    = *srv_addr;
	a->remote_port = remote_port;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_close(iprcchan_t *chan, rem_pico_socket_t *s)
{
	rem_arg_t                   *arg = iprcchan_begin_call(chan);
	rem_res_t                   *res = (rem_res_t*)arg;
	rem_pico_socket_close_arg_t *a = &arg->u.rem_pico_socket_close_arg;
	rem_pico_socket_close_res_t *r = &res->u.rem_pico_socket_close_res;
	int                          retval;

	arg->hdr.func = f_rem_pico_socket_close;
	a->s          = s;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_bind(iprcchan_t *chan, rem_pico_socket_t *s, union pico_address *local_addr, uint16_t *port)
{
	rem_arg_t                  *arg = iprcchan_begin_call(chan);
	rem_res_t                  *res = (rem_res_t*)arg;
	rem_pico_socket_bind_arg_t *a = &arg->u.rem_pico_socket_bind_arg;
	rem_pico_socket_bind_res_t *r = &res->u.rem_pico_socket_bind_res;
	int                         retval;

	arg->hdr.func = f_rem_pico_socket_bind;
	a->s          = s;
	a->local_addr = *local_addr;
	a->port       = *port;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	*port    = r->port;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_getname(iprcchan_t *chan, rem_pico_socket_t *s, union pico_address *local_addr, uint16_t *port, uint16_t *proto, int peer)
{
	rem_arg_t                     *arg = iprcchan_begin_call(chan);
	rem_res_t                     *res = (rem_res_t*)arg;
	rem_pico_socket_getname_arg_t *a = &arg->u.rem_pico_socket_getname_arg;
	rem_pico_socket_getname_res_t *r = &res->u.rem_pico_socket_getname_res;
	int                            retval;

	arg->hdr.func = f_rem_pico_socket_getname;
	a->s          = s;
	a->peer       = peer;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	*local_addr = r->local_addr;
	*port       = r->port;
	*proto      = r->proto;
	iprcchan_end_call(chan);
	return retval;
}

rem_pico_socket_t *rem_pico_socket_accept(iprcchan_t *chan, rem_pico_socket_t *s, union pico_address *orig, uint16_t *port)
{
	rem_arg_t                    *arg = iprcchan_begin_call(chan);
	rem_res_t                    *res = (rem_res_t*)arg;
	rem_pico_socket_accept_arg_t *a = &arg->u.rem_pico_socket_accept_arg;
	rem_pico_socket_accept_res_t *r = &res->u.rem_pico_socket_accept_res;
	rem_pico_socket_t            *retval;

	arg->hdr.func = f_rem_pico_socket_accept;
	a->s          = s;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	*orig       = r->orig;
	*port       = r->port;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_listen(iprcchan_t *chan, rem_pico_socket_t *s, const int backlog)
{
	rem_arg_t                     *arg = iprcchan_begin_call(chan);
	rem_res_t                     *res = (rem_res_t*)arg;
	rem_pico_socket_listen_arg_t  *a = &arg->u.rem_pico_socket_listen_arg;
	rem_pico_socket_listen_res_t  *r = &res->u.rem_pico_socket_listen_res;
	int                            retval;

	arg->hdr.func = f_rem_pico_socket_listen;
	a->s          = s;
	a->backlog    = backlog;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_sendto(iprcchan_t *chan, rem_pico_socket_t *s, const void *buf, int len, union pico_address *dst, uint16_t remote_port)
{
	rem_arg_t                    *arg = iprcchan_begin_call(chan);
	rem_res_t                    *res = (rem_res_t*)arg;
	rem_pico_socket_sendto_arg_t *a = &arg->u.rem_pico_socket_sendto_arg;
	rem_pico_socket_sendto_res_t *r = &res->u.rem_pico_socket_sendto_res;
	int                           retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func  = f_rem_pico_socket_sendto;
	a->s           = s;
	a->len         = len;
	a->dst         = *dst;
	a->remote_port = remote_port;
	memcpy(&a->buf[0], buf, len);
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_sendto_msg(iprcchan_t *chan, rem_pico_socket_t *s, struct msghdr *msg, int len, union pico_address *dst, uint16_t remote_port)
{
	rem_arg_t                    *arg = iprcchan_begin_call(chan);
	rem_res_t                    *res = (rem_res_t*)arg;
	rem_pico_socket_sendto_arg_t *a = &arg->u.rem_pico_socket_sendto_arg;
	rem_pico_socket_sendto_res_t *r = &res->u.rem_pico_socket_sendto_res;
	int                           retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func  = f_rem_pico_socket_sendto;
	a->s           = s;
	a->len         = len;
	a->dst         = *dst;
	a->remote_port = remote_port;
	if (memcpy_from_msg(&a->buf[0], msg, len) >= 0) {
		do_call(chan);
		pico_err = res->hdr.pico_err;
		retval   = r->retval;
	}
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_send(iprcchan_t *chan, rem_pico_socket_t *s, const void *buf, int len)
{
	rem_arg_t                  *arg = iprcchan_begin_call(chan);
	rem_res_t                  *res = (rem_res_t*)arg;
	rem_pico_socket_send_arg_t *a = &arg->u.rem_pico_socket_send_arg;
	rem_pico_socket_send_res_t *r = &res->u.rem_pico_socket_send_res;
	int                         retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func  = f_rem_pico_socket_send;
	a->s           = s;
	a->len         = len;
	memcpy(&a->buf[0], buf, len);
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_send_msg(iprcchan_t *chan, rem_pico_socket_t *s, struct msghdr *msg, int len)
{
	rem_arg_t                  *arg = iprcchan_begin_call(chan);
	rem_res_t                  *res = (rem_res_t*)arg;
	rem_pico_socket_send_arg_t *a = &arg->u.rem_pico_socket_send_arg;
	rem_pico_socket_send_res_t *r = &res->u.rem_pico_socket_send_res;
	int                         retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func  = f_rem_pico_socket_send;
	a->s           = s;
	a->len         = len;
	retval = memcpy_from_msg(&a->buf[0], msg, len);
	if (retval >= 0) {
		do_call(chan);
		pico_err = res->hdr.pico_err;
		retval   = r->retval;
	}
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_recvfrom(iprcchan_t *chan, rem_pico_socket_t *s, void *buf, int len, union pico_address *orig, uint16_t *local_port)
{
	rem_arg_t                      *arg = iprcchan_begin_call(chan);
	rem_res_t                      *res = (rem_res_t*)arg;
	rem_pico_socket_recvfrom_arg_t *a = &arg->u.rem_pico_socket_recvfrom_arg;
	rem_pico_socket_recvfrom_res_t *r = &res->u.rem_pico_socket_recvfrom_res;
	int                             retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func = f_rem_pico_socket_recvfrom;
	a->s          = s;
	a->len        = len;
	a->lock       = 1;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	*orig       = r->orig;
	*local_port = r->local_port;
	if (retval > 0)
		memcpy(buf, &r->buf[0], retval);
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_recvfrom2(iprcchan_t *chan, rem_pico_socket_t *s, void *buf, int len, union pico_address *orig, uint16_t *local_port, int lock, int *more)
{
	rem_arg_t                      *arg = iprcchan_begin_call(chan);
	rem_res_t                      *res = (rem_res_t*)arg;
	rem_pico_socket_recvfrom_arg_t *a = &arg->u.rem_pico_socket_recvfrom_arg;
	rem_pico_socket_recvfrom_res_t *r = &res->u.rem_pico_socket_recvfrom_res;
	int                             retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func = f_rem_pico_socket_recvfrom;
	a->s          = s;
	a->len        = len;
	a->lock       = lock;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	*orig       = r->orig;
	*local_port = r->local_port;
	*more       = r->more;
	if (retval > 0)
		memcpy(buf, &r->buf[0], retval);
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_recvfrom_msg(iprcchan_t *chan, rem_pico_socket_t *s, struct msghdr *msg, int len, union pico_address *orig, uint16_t *local_port)
{
	rem_arg_t                      *arg = iprcchan_begin_call(chan);
	rem_res_t                      *res = (rem_res_t*)arg;
	rem_pico_socket_recvfrom_arg_t *a = &arg->u.rem_pico_socket_recvfrom_arg;
	rem_pico_socket_recvfrom_res_t *r = &res->u.rem_pico_socket_recvfrom_res;
	int                             retval;

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;
	else if (len < 0)
		len = 0;
	arg->hdr.func = f_rem_pico_socket_recvfrom;
	a->s          = s;
	a->len        = len;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	*orig       = r->orig;
	*local_port = r->local_port;
	if (retval > 0) {
		memcpy_to_msg(msg, &r->buf[0], retval);
	}
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_udp_poll(iprcchan_t *chan, rem_pico_socket_t *s)
{
	rem_arg_t                      *arg = iprcchan_begin_call(chan);
	rem_res_t                      *res = (rem_res_t*)arg;
	rem_pico_socket_udp_poll_arg_t *a = &arg->u.rem_pico_socket_udp_poll_arg;
	rem_pico_socket_udp_poll_res_t *r = &res->u.rem_pico_socket_udp_poll_res;
	int                             retval;

	arg->hdr.func = f_rem_pico_socket_udp_poll;
	a->s          = s;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_tcp_poll(iprcchan_t *chan, rem_pico_socket_t *s)
{
	rem_arg_t                      *arg = iprcchan_begin_call(chan);
	rem_res_t                      *res = (rem_res_t*)arg;
	rem_pico_socket_tcp_poll_arg_t *a = &arg->u.rem_pico_socket_tcp_poll_arg;
	rem_pico_socket_tcp_poll_res_t *r = &res->u.rem_pico_socket_tcp_poll_res;
	int                             retval;

	arg->hdr.func = f_rem_pico_socket_tcp_poll;
	a->s          = s;
	do_call(chan);
	pico_err    = res->hdr.pico_err;
	retval      = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

rem_pico_socket_t *rem_pico_socket_open(iprcchan_t *chan, uint16_t net, uint16_t proto)
{
	rem_arg_t                  *arg = iprcchan_begin_call(chan);
	rem_res_t                  *res = (rem_res_t*)arg;
	rem_pico_socket_open_arg_t *a = &arg->u.rem_pico_socket_open_arg;
	rem_pico_socket_open_res_t *r = &res->u.rem_pico_socket_open_res;
	rem_pico_socket_t          *retval;

	arg->hdr.func = f_rem_pico_socket_open;
	a->net        = net;
	a->proto      = proto;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_getoption(iprcchan_t *chan, rem_pico_socket_t *s, int option, void *value, int *optlen)
{
	rem_arg_t                       *arg = iprcchan_begin_call(chan);
	rem_res_t                       *res = (rem_res_t*)arg;
	rem_pico_socket_getoption_arg_t *a = &arg->u.rem_pico_socket_getoption_arg;
	rem_pico_socket_getoption_res_t *r = &res->u.rem_pico_socket_getoption_res;
	int                              retval;

	if (*optlen > REM_BUFFSIZE)
		*optlen = REM_BUFFSIZE;
	else if (*optlen < 0)
		*optlen = 0;
	arg->hdr.func = f_rem_pico_socket_getoption;
	a->s      = s;
	a->option = option;
	a->optlen = *optlen;
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	*optlen  = r->optlen;
	if (retval > 0)
		memcpy(value, &r->value[0], *optlen);
	iprcchan_end_call(chan);
	return retval;
}

int rem_pico_socket_setoption(iprcchan_t *chan, rem_pico_socket_t *s, int option, void *value, int optlen)
{
	rem_arg_t                       *arg = iprcchan_begin_call(chan);
	rem_res_t                       *res = (rem_res_t*)arg;
	rem_pico_socket_setoption_arg_t *a = &arg->u.rem_pico_socket_setoption_arg;
	rem_pico_socket_setoption_res_t *r = &res->u.rem_pico_socket_setoption_res;
	int                              retval;

	if (optlen > REM_BUFFSIZE)
		optlen = REM_BUFFSIZE;
	else if (optlen < 0)
		optlen = 0;
	arg->hdr.func = f_rem_pico_socket_setoption;
	a->s      = s;
	a->option = option;
	a->optlen = optlen;
	memcpy(&a->value[0], value, optlen);
	do_call(chan);
	pico_err = res->hdr.pico_err;
	retval   = r->retval;
	iprcchan_end_call(chan);
	return retval;
}
