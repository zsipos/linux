// SPDX-FileCopyrightText: 2020 Stefan Adams <stefan.adams@vipcomag.de>
// SPDX-License-Identifier: GPL-2.0

#ifndef _H_DOIOCTL_H
#define _H_DOIOCTL_H

extern int doioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

#endif
