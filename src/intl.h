/*
 * intl.h -- description
 * Part of the GNU netcat project
 *
 * Author: Giovanni Giacobbi <johnny@themnemonic.org>
 * Copyright (C) 2002  Giovanni Giacobbi
 *
 * $Id: intl.h,v 1.3 2002-05-05 09:05:58 themnemonic Exp $
 */

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 ***************************************************************************/

#ifdef ENABLE_NLS
#include <libintl.h>

#ifdef HAVE_LOCALE_H
#include <locale.h>
#else
#error "You must have locale.h in your system"
#endif	/* HAVE_LOCALE_H */

/* Our dear (and very common) gettext macros */
#define _(String) gettext(String)
#define N_(String) String
#define PL_(String1, String2, n) ngettext((String1), (String2), (n))

#else

#define _(String) (String)
#define N_(String) String
#define PL_(String1, String2, n) ((n) == 1 ? (String1) : (String2))

#define textdomain(Domain)
#define bindtextdomain(Package, Directory)

#endif	/* ENABLE_NLS */
