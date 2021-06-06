/*
#
# Copyright (C) 2018 University of Southern California.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
*/

#include <signal.h>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sched.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <monetary.h>
#include <locale.h>
#include <regex.h>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <cmath>
#include <pcap.h>
#include <dirent.h>

using namespace std;

const int MAXLINE=1024;

int main(int argc, char** argv)
{
while(1)
  {
    char line[MAXLINE];
    char* rc = fgets(line, MAXLINE-1,stdin);
    if (rc == 0)
      break;

    // Sanity check for Flowride to get rid of stray chars      
    int i = strlen(line)-1;
    int found = 0;
    for(; i>0; i--)
      {
	if (line[i] == '\t')
	  found++;
	if (found == 19)
	  {
	    i-=19;
	    break;
	  }
      }
    // Ignore if there's apostrophe
    if (i > 1 && found == 19)
      {
	cout<<"Control chars in line "<<line<<endl;
      }
  }
}
