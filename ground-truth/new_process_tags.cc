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
#include <set>
#include <cmath>
#include <pcap.h>
#include <dirent.h>


// Limits
#include<bits/stdc++.h> 

#include "utils.h"


#define BILLION 1000000000L
#define DAY 86400
#define MINV 1.1
#define MINS 3600
#define THRESH 10
#define NUMSTD 3
#define LIMITSIZE 100

using namespace std;


// Global variables
bool resetrunning = false;
int numattack = 0;

// We store delimiters in this array
int* delimiters;
string label;

struct bcell {
  int srcs;
  int vol;
  int flows;
  map<int, int> tag;
};

enum type {TOTAL, UDPT, ICMPT,  SYNT, ACKT, NTPR, DNSR, FRAG, LDAPR, SYNACKT, RSTT, MDNS, CGEN, L2TP, MCHD, DNS, RPC};

struct cell {
  map<type, bcell> data;
};

map<unsigned int, map<unsigned int, cell>> stats;

enum celltype {SRC, VOL, FLOW};

map <celltype, int> allowed;


// hold values for each src/bytes/flows
// for statistics
struct ccell{
  int max;
  double mean;
  double ss;
  double cusum;
};
  
struct record {
  int n;
  unsigned int stime;
  map<celltype, ccell> records;
};


map<unsigned int, map<type, record>> metrics;

struct attack
{
  unsigned int start;
  unsigned int end;
  set <enum type> atypes;
  int dur;
  int gap;
};
  
map<int, map<unsigned int, attack>> attacks;

map<int, int> tagmap;

//  Print out stats


// Something like strtok but it doesn't create new
// strings. Instead it replaces delimiters with 0
// in the original string
int parse(char* input, char delimiter1, char delimiter2,  int** array)
{
  int pos = 0;
  memset(*array, 255, AR_LEN);
  int len = strlen(input);
  int found = 0;
  for(int i = 0; i<len; i++)
    {
      if (input[i] == delimiter1 || input[i] == delimiter2)
	{
	  (*array)[pos] = i+1;
	  input[i] = 0;
	  pos++;
	  found++;
	}
    }
  return found;
}


// Current time
double curtime = 0;
double lasttime = 0;
double lastlogtime = 0;
double lastbintime = 0;
unsigned int starttime = 0;
unsigned int endtime = 0;
 

// Verbose bit
int verbose = 0;

double firsttime = 0;       // Beginning of trace 
long freshtime = 0;       // Where we last ended when processing data 
double firsttimeinfile = 0; // First time in the current file
long int allflows = 0;          // How many flows were processed total
long int processedflows = 0;    // How many flows were processed this second
long updatetime = 0;      // Time of last stats update
long statstime = 0;       // Time when we move the stats to history 
char filename[MAXLINE];   // A string to hold filenames
struct timespec last_entry;

// Is this pcap file or flow file? Default is flow
bool is_pcap = false;
bool is_live = false;
bool is_nfdump = false;
bool is_flowride = false;

// Keeping track of procesed flows
long int processedbytes = 0;
int nl = 0;
int l = 0;
int mal = 0;
int inserts = 0;
int cinserts = 0;

// Trim strings 
char *trim(char *str)
{
    size_t len = 0;
    char *frontp = str;
    char *endp = NULL;

    if( str == NULL ) { return NULL; }
    if( str[0] == '\0' ) { return str; }

    len = strlen(str);
    endp = str + len;

    while( isspace((unsigned char) *frontp) ) { ++frontp; }
    if( endp != frontp )
    {
        while( isspace((unsigned char) *(--endp)) && endp != frontp ) {}
    }

    if( str + len - 1 != endp )
            *(endp + 1) = '\0';
    else if( frontp != str &&  endp == frontp )
            *str = '\0';

    endp = str;
    if( frontp != str )
    {
            while( *frontp ) { *endp++ = *frontp++; }
            *endp = '\0';
    }

    return str;
}




// Update statistics
void update_stats(cell* c)
{

}

	



// Print help for the program
void
printHelp (void)
{
  printf ("amon-senss\n(C) 2018 University of Southern California.\n\n");

  printf ("-h                             Print this help\n");
  printf ("-r <file>                      Input is in given file gzipped\n");
}



// Define the function to be called when ctrl-c (SIGINT) is sent to process
void signal_callback_handler(int signum) {
   cout << "Caught signal " << signum << endl;
   // Terminate program
   exit(signum);
}

// Convert address to IP string
/*
string toip(unsigned int addr)
{
  string out="";
  int div = 256*256*256;
  while (div > 0)
    {
      unsigned int r = (unsigned int)addr/div;
      addr = addr - r*div;
      div /= 256;
      if (out != "")
	out = out + ".";
      out = out + patch::to_string(r);
    }
  return out;
}
*/


// Convert string to address
 /*
unsigned int todec(string ip)
{
  int res = 0;
  int dec = 0;
  for (int i=0; i<strlen(ip.c_str()); i++)
    if (isdigit(ip[i]))
      dec = dec*10+(ip[i]-'0');
    else
      {
        res = res*256+dec;
        dec = 0;
      }
  res = res*256+dec;
  return res;
}
 */

void read_tags()
{
  char *s, buff[256];
  int mapin, mapout;
  ifstream fp("maptags.txt", ios::in);
  if (!fp.is_open())
    {
      cout<<"Cannot map tags\n";
      exit (0);
    }
  while(true)
    {
      fp>>buff>>mapin>>mapout;
      tagmap[mapout] = mapin;
      if (fp.eof())
	{
	  fp.close();
	  break;
	}
    }
 }

// Read one line from file according to format
double read_one_line(void* nf, char* line)
{
  char* s = fgets(line, 100*MAXLINE, (FILE*) nf);
  if (s == NULL)
    return -1;
  int dl = parse(line,' ', ',', &delimiters);
  if (dl > 0)
    {
      int nh = int(dl/52);
      unsigned int ip = todec(line);
      unsigned int time = atol(line+delimiters[0]);

      if (starttime == 0 || time < starttime)
	starttime = time;
      if (endtime < time)
	{
	  endtime = time;
	}
      if (stats.find(ip) == stats.end())
        {
          map<unsigned int, cell> a;
          stats[ip] = a;
	}
      if (stats[ip].find(time) == stats[ip].end())
        {
          map<type,bcell> b;
          stats[ip][time].data = b;
        }
      
      for(int i=1; i<dl-nh-2; i+=53) // trailing comma
	{
	  bcell b;

	  enum type t = (enum type)atoi(line+delimiters[i]);
	  b.srcs = atoi(line+delimiters[i+1]);
	  b.vol = atoi(line+delimiters[i+2]);
	  b.flows = atoi(line+delimiters[i+3]);
	  for (int j=4; j<52; j++)
	    {
	      string s = line+delimiters[i+j];
	      if (s.rfind("A", 0)  != string::npos)
		b.tag[j-4] = atoi(s.c_str()+1);
	      else
		b.tag[j-4] = 0;
	    }
	  stats[ip][time].data[(enum type)t] = b;

	  for (int j=0; j<48; j++)
	    {
	      bool found = false;
	      if (b.tag[j] == 7 || b.tag[j] == 5 || b.tag[j] == 3)
		{

		  if (attacks[j].find(ip) == attacks[j].end())
		    {
		      attack a;
		      a.start = time;
		      a.end = time;
		      a.dur = 1;
		      a.gap = 0;
		      a.atypes.insert(t);
		      attacks[j][ip] = a;
		    }
		  else
		    {
		      if (attacks[j][ip].atypes.find(t) == attacks[j][ip].atypes.end())
			attacks[j][ip].atypes.insert(t);
		      found = true;	  
		      attacks[j][ip].gap = 0;
		      attacks[j][ip].end = time;
		    }		  
		}	 
	      if (found)
		{
		  attacks[j][ip].dur++;
		}
	      else
		{
		  if (attacks[j].find(ip) != attacks[j].end())
		    {
		      attacks[j][ip].gap++;
		      if (attacks[j][ip].gap >= 2*THRESH)
			{
			  if (attacks[j][ip].dur >= THRESH)
			    {
			      int tt = 0;
			      cout<<j<<": Attack on "<<toip(ip)<<" from "<<attacks[j][ip].start<<" to "<<attacks[j][ip].end<<" dur "<<attacks[j][ip].dur<<" types ";
			      for (auto at=attacks[j][ip].atypes.begin(); at != attacks[j][ip].atypes.end(); at++)
				{
				  tt = tt | tagmap[*at];
				}
			      if (tt > 128 && (tt & 128))
				tt = tt - 128;
			      if (tt != 4 && (tt & 4))
				tt = tt - 4;
			      cout<<tt<<endl;
			    }
			  attacks[j].erase(ip);
			}
		    }
		}
	    }
	}
      return 1;
    }
  else
    return 0;
}


// Read from file according to format
void read_from_file(void* nf, char* format)
{
  // -1 means EOF, 0 means line without a flow
  char line[100*MAXLINE];
  double epoch;
  int num_pkts = 0;
  double start = time(0);
  u_char* p;
  struct pcap_pkthdr *h;
  for (int j=0; j<48; j++)
    {
      map <unsigned int, attack> m;
      attacks[j] = m;
    }
  while ((epoch = read_one_line(nf, line)) != -1);
  for (int j=0; j<48; j++)
    {
      for (auto it = attacks[j].begin(); it != attacks[j].end(); it++)
	{
	  unsigned int ip = it->first;
	  if (attacks[j][ip].dur >= THRESH)
	    {
	      int tt = 0;
	      cout<<j<<": Attack on "<<toip(ip)<<" from "<<attacks[j][ip].start<<" to "<<attacks[j][ip].end<<" dur "<<attacks[j][ip].dur<<" types ";
	      for (auto at=attacks[j][ip].atypes.begin(); at != attacks[j][ip].atypes.end(); at++)
		{
		  tt = tt | tagmap[*at];
		}
	      if (tt > 128 && (tt & 128))
		tt = tt - 128;
	      if (tt != 4 && (tt & 4))
		tt = tt - 4;
	      cout<<tt<<endl;
	    }
	}
    }
}


// Main program
int main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  
  char c, buf[32];
  char *file_in = NULL;
  bool stream_in = false;
  char *startfile = NULL, *endfile = NULL;
  char* format;
  
  while ((c = getopt (argc, argv, "hr:")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'h':
	  printHelp ();
	  return (0);
	  break;
	case 'r':
	  file_in = strdup(optarg);
	  label = file_in;
	  break;
	}
    }
  if (file_in == NULL)
    {
      cerr<<"You must specify the file with statistics\n";
      exit(-1);
    }
  char cmd[MAXLINE];
  FILE* nf;
  
  read_tags();
  sprintf(cmd,"gunzip -c %s", file_in);
  nf = popen(cmd, "r");
  read_from_file(nf, format);
  return 0;
}
