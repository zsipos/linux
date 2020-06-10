#ifndef _H_DOIOCTL_H
#define _H_DOIOCTL_H

extern int doioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

#endif
