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
#define DUR 10
#define GAP 30
#define PKTS 1000
#define SRCS 1
#define NUMSTD 3
#define LIMITSIZE 100

using namespace std;


// Global variables
bool resetrunning = false;
char saveline[MAXLINE];
int numattack = 0;
int THRESH;

// We store delimiters in this array
int* delimiters;
string label;

struct bcell {
  int srcs;
  int vol;
  int pkts;
  int tag;
  int dsts;
  int rvol;
  int rpkts;
  int rtag;
};

enum type {TOTAL, UDPT, ICMPT,  SYNT, ACKT, NTPR, DNSR, FRAG, LDAPR, SYNACKT, RSTT, MDNS, CGEN, L2TP, MCHD, DNS, RPC};

struct cell {
  map<type, bcell> data;
};


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
  unsigned int ltime;
  unsigned int start;
  unsigned int end;
  int rate;
  map <enum type, unsigned int> atypes;
  int dur;
  int gap;
};
  
map<unsigned int, attack> attacks;

map<int, int> tagmap;

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
  printf ("-t thresh                      Threshold value for attack\n");
}



// Define the function to be called when ctrl-c (SIGINT) is sent to process
void signal_callback_handler(int signum) {
   cout << "Caught signal " << signum << endl;
   // Terminate program
   exit(signum);
}

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
  char* s = fgets(line, MAXLINE, (FILE*) nf);
  if (s == NULL)
    return -1;
  char saveline[1000];
  strcpy(saveline, line);
  int dl = parse(line,' ', ',', &delimiters);
  if (dl > 0)
    {
      unsigned int ip = todec(line);
      unsigned int time = atol(line+delimiters[0]);

      if (starttime == 0 || time < starttime)
	starttime = time;
      if (endtime < time)
	{
	  endtime = time;
	}

      bool found = false;
      double frate = 0;

      // Ignore UDP floods and total traffic and just work on the rest
      for(int i=19; i<dl-1; i+=9) // trailing comma
	{
	  bcell b;
	  enum type t = (enum type)atoi(line+delimiters[i]);
	  //cout<<"Line "<<saveline<<" type "<<t<<" i "<<i<<" dl "<<dl<<endl;
	  b.srcs = atoi(line+delimiters[i+1]);
	  b.vol = atoi(line+delimiters[i+2]);
	  b.pkts = atoi(line+delimiters[i+3]);
	  try {
	    b.tag = stod(line+delimiters[i+4]);
	  }
	  catch (const std::out_of_range& oor) {
	    b.tag = 0;
	  }
	  b.dsts = atoi(line+delimiters[i+5]);
	  b.rvol = atoi(line+delimiters[i+6]);
	  b.rpkts = atoi(line+delimiters[i+7]);
	  try {
	    b.rtag = stod(line+delimiters[i+8]);
	  }
	  catch (const std::out_of_range& oor) {
	    b.rtag = 0;
	  }

	  if (b.tag >= THRESH)
	    {
	      if (attacks.find(ip) == attacks.end())
		{
		  attack a;
		  a.start = time;
		  a.ltime = time;
		  a.end = time;
		  a.dur = 1;
		  a.rate = b.pkts;
		  a.gap = 0;
		  attacks[ip] = a;
		}
	      else
		{
		  found = true;
		  if (frate < b.pkts)
		    frate = b.pkts;
		}
	    }
	}
      if (found)
	{
	  int diff = time - attacks[ip].ltime;
	  attacks[ip].gap += diff;
	  if (attacks[ip].gap >= GAP)
	    {
	      cout<<"Potential attack on "<<toip(ip)<<" start "<<std::fixed<<attacks[ip].start<<" dur "<<attacks[ip].dur<<" rate "<<attacks[ip].rate<<" types ";
	      int tt = 0;
	      unsigned long total = 0;
	      for (auto at=attacks[ip].atypes.begin(); at != attacks[ip].atypes.end(); at++)
                    {
                      //cout<<" type "<<at->first<<" flows "<<at->second<<endl;                                                                               
                      if ((int)at->first == 0)
                        {
                          total = at->second;
                        }
                      else if (at->second >= 0.05*total)
                        {
                          tt = tt | tagmap[at->first];
                        }
                    }
                  if (tt > 128 && (tt & 128))
                    tt = tt - 128;
                  if (tt != 4 && (tt & 4))
                    tt = tt - 4;
                  cout<<tt<<endl;

	      
	      if (attacks[ip].dur >= DUR)
		{
		  int tt = 0;
		  cout<<"Attack on "<<toip(ip)<<" from "<<attacks[ip].start<<" to "<<attacks[ip].end<<" dur "<<attacks[ip].dur<<" rate "<<attacks[ip].rate<<" types ";
		  unsigned long total = 0;
		  for (auto at=attacks[ip].atypes.begin(); at != attacks[ip].atypes.end(); at++)
		    {
		      //cout<<" type "<<at->first<<" flows "<<at->second<<endl;
		      if ((int)at->first == 0)
			{
			  total = at->second;
			}
		      else if (at->second >= 0.05*total)
			{
			  tt = tt | tagmap[at->first];
			}
		    }
		  if (tt > 128 && (tt & 128))
		    tt = tt - 128;
		  if (tt != 4 && (tt & 4))
		    tt = tt - 4;
		  cout<<tt<<endl;
		}
	      attacks[ip].gap = 0;
	      attacks[ip].dur = 0;
	      attacks[ip].start = time;
	      attacks[ip].rate = frate;
	      attacks[ip].atypes.clear();
	    }
	  else
	    {
	      if (attacks[ip].rate < frate)
		attacks[ip].rate = frate;
	      attacks[ip].gap = 0;
	      attacks[ip].end = time;
	    }
	attacks[ip].dur++;
	attacks[ip].ltime = time;
	}
      for(int i=19; i<dl-1; i+=9) // trailing comma
	{
	  enum type t = (enum type)atoi(line+delimiters[i]);
	  int pkts = atoi(line+delimiters[i+3]);
	  double tag = 0;
	  try
	    {
	      tag = stod(line+delimiters[i+4]);
	    }
	  catch (const std::out_of_range& oor) {
	  }
	  
	  if (tag > THRESH)
	    {
	      if (attacks[ip].atypes.find(t) == attacks[ip].atypes.end())
		attacks[ip].atypes[t] = pkts;
	      else
		attacks[ip].atypes[t] += pkts;
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
  char line[MAXLINE];
  double epoch;
  int num_pkts = 0;
  double start = time(0);
  u_char* p;
  struct pcap_pkthdr *h;
  while ((epoch = read_one_line(nf, line)) != -1);
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
  
  while ((c = getopt (argc, argv, "hr:t:")) != '?')
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
	case 't':
	  THRESH = atoi(optarg);
	  break;
	}
    }
  if (file_in == NULL)
    {
      cerr<<"You must specify the file with statistics\n";
      exit(-1);
    }
  if (THRESH == 0)
    {
      cerr<<"You must specify the threshold\n";
      exit(-1);
    }
  read_tags();

    int isdir = 0;
  vector<string> tracefiles;
  vector<string> inputs;
  struct stat s;
  inputs.push_back(file_in);
  int i = 0;
  // Recursively read if there are several directories that hold the files
  while(i < inputs.size())
    {
      if(stat(inputs[i].c_str(),&s) == 0 )
	{
	  if(s.st_mode & S_IFDIR )
	    {
	      // it's a directory, read it and fill in 
	      // list of files
	      DIR *dir;
	      struct dirent *ent;
	      
	      if ((dir = opendir (inputs[i].c_str())) != NULL) {
		// Remember all the files and directories within directory 
		while ((ent = readdir (dir)) != NULL) {
		  if((strcmp(ent->d_name,".") != 0) && (strcmp(ent->d_name,"..") != 0)){
		    inputs.push_back(string(inputs[i]) + "/" + string(ent->d_name));
		  }
		}
		closedir (dir);
	      } else {
		perror("Could not read directory ");
		exit(1);
	      }
	    }
	  else if(s.st_mode & S_IFREG)
	    {
	      tracefiles.push_back(inputs[i]);
	    }
	  // Ignore other file types
	}
      i++;
    }
  inputs.clear();
  
  //tracefiles.push_back(file_in);
  
  std::sort(tracefiles.begin(), tracefiles.end(), sortbyFilename());
  for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
    {
      cout<<"Files to read "<<vit->c_str()<<endl;
    }
  int started = 1;
  if (startfile != NULL)
    started = 0;
  double start = time(0);
  // Go through tracefiles and read each one
  // Jelena: should delete after reading
  for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
    {
      const char* file = vit->c_str();
      
      if (!started && startfile && strstr(file,startfile) == NULL)
	{
	  continue;
	}
      
      started = 1;
      
      // Now read from file
      cout<<"Reading from "<<file<<endl;

      char cmd[MAXLINE];
      FILE* nf;
  
      
      sprintf(cmd,"gunzip -c %s", file);
      nf = popen(cmd, "r");
      read_from_file(nf, format);
    }
    for (auto it = attacks.begin(); it != attacks.end(); it++)
    {
      unsigned int ip = it->first;
      cout<<"Potential attack 2 on "<<toip(ip)<<" dur "<<attacks[ip].dur<<endl;
      if (attacks[ip].dur >= DUR)
	{
	  int tt = 0;
	  cout<<"Attack on "<<toip(ip)<<" from "<<attacks[ip].start<<" to "<<attacks[ip].end<<" dur "<<attacks[ip].dur<<" rate "<<attacks[ip].rate<<" types ";
	  unsigned long total = 0;
	  for (auto at=attacks[ip].atypes.begin(); at != attacks[ip].atypes.end(); at++)
	    {
	      if ((int)at->first == 0)
		{
		  total = at->second;
		}
	      else if (at->second >= 0.05*total)
		{
		  tt = tt | tagmap[at->first];
		}
	    }
	  if (tt > 128 && (tt & 128))
	    tt = tt - 128;
	  if (tt != 4 && (tt & 4))
	    tt = tt - 4;
	  cout<<tt<<endl;
	}
    }
}
