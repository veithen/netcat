# Copyright (C) 2013  Andreas Veithen <andreas.veithen@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA or point your web browser to http://www.gnu.org.

import socket
import errno
import time

def allocate_tcp_port():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(('', 0))
  port = s.getsockname()[1]
  s.close()
  return port

def __safe_connect(self, address):
  attempt = 0
  while True:
    attempt += 1
    try:
      self.connect(address)
      return
    except socket.error as e:
      if e.errno != errno.ECONNREFUSED or attempt > 10:
        raise e
      else:
        time.sleep(0.2)

socket._socketobject.safe_connect = __safe_connect
