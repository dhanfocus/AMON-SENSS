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

#define THRESH 5
#define NUMSTD 3
#define LIMITSIZE 100
#define BETA 0.9
using namespace std;


// Global variables
double lambda = 0.9;
bool resetrunning = false;
char saveline[MAXLINE];
int numattack = 0;

// We store delimiters in this array
int* delimiters;
string label;

struct bcell {
  int srcs;
  unsigned long int vol;
  int pkts;
  double tag;
  int dsts;
  unsigned long int rvol;
  int rpkts;
  double rtag;
};

enum type {TOTAL, UDPT, ICMPT,  SYNT, ACKT, NTPR, DNSR, FRAG, LDAPR, SYNACKT, RSTT, MDNS, CGEN, L2TP, MCHD, DNS, RPC, USERDEF};

struct cell {
  map<type, bcell> data;
};

struct statsr {
  int maxs;
  map<unsigned int, cell> statsdata;
  bool tagged;
};

map<unsigned int, statsr> stats;

enum celltype {SRC, VOL, PKTS, DST, RVOL, RPKTS};

map <celltype, int> allowed;


// hold values for each src/bytes/flows
// for statistics
struct ccell{
  int max;
  double mean;
  double sum;
  double ss;
  double stdev;
  double cusum;
  double last;
};
  
struct record {
  double n;
  unsigned int stime;
  unsigned int ltime;
  map<celltype, ccell> records;
};


map<unsigned int, map<type, record>> metrics;

//  Print out stats
void print_stats(string file)
{
  ofstream out;
  out.open(file, std::ios_base::app);

  int i = 0;
  //cout<<"printing stats"<<endl;
  for(auto it = stats.begin(); it != stats.end(); it++)
    {
      for (auto iit = it->second.statsdata.begin(); iit != it->second.statsdata.end(); iit++)
	{
	  bool nonzero = false;
	  for (auto dit = iit->second.data.begin(); dit != iit->second.data.end(); dit++)
	    {
	      if (dit->second.srcs > 0)
		nonzero = true;
	    }
	  //cout<<"Nonzero "<<nonzero<<endl;
	  if (nonzero && it->second.tagged)
	    {
	      out<<toip(it->first)<<" "<<iit->first<<" ";
	      for (auto dit = iit->second.data.begin(); dit != iit->second.data.end(); dit++)
		{
		  out<<dit->first<<" "<<dit->second.srcs<<" "<<dit->second.vol<<" "<<dit->second.pkts<<" "<<dit->second.tag<<" "<<dit->second.dsts<<" "<<dit->second.rvol<<" "<<dit->second.rpkts<<" "<<dit->second.rtag<<",";
		}
	      out<<endl;
	    }
	}
      if (it->second.tagged)
	it->second.statsdata.clear();
    }
  out.close();
}


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
bool started = false;
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
 
// Read one line from file according to format
double read_one_line(void* nf, char* line)
{
  char* s = fgets(line, MAXLINE, (FILE*) nf);  
  if (s == NULL)
    return -1;

  strcpy(saveline, s);

  int dl = parse(line,' ', ',', &delimiters);
  if (dl > 0)
    {
      unsigned int ip = todec(line);
      unsigned int time = atol(line+delimiters[0]);
      if (starttime == 0)
	{
	  starttime = time;
	  cout<<"Starttime "<<starttime<<endl;
	}
      if (endtime < time)
	{
	  endtime = time;
	}
      if (stats.find(ip) == stats.end())
        {
          map<unsigned int, cell> a;
          stats[ip].statsdata = a;
	  stats[ip].maxs = 0;
	}
      if (stats[ip].statsdata.find(time) == stats[ip].statsdata.end())
        {
          map<type,bcell> b;
          stats[ip].statsdata[time].data = b;
	  //cout<<"Inserted time "<<time<<endl;
        }
      
      for(int i=1; i<dl-1; i+=7) // trailing comma
	{
	  int t = atoi(line+delimiters[i]);
	  bcell b;
	  b.srcs = atoi(line+delimiters[i+1]);
	  b.vol = atoi(line+delimiters[i+2]);
	  b.pkts = atoi(line+delimiters[i+3]);
	  b.tag = 0;
	  b.dsts = atoi(line+delimiters[i+4]);
	  b.rvol = atoi(line+delimiters[i+5]);
	  b.rpkts = atoi(line+delimiters[i+6]);
	  b.rtag = 0;
	  stats[ip].statsdata[time].data[(enum type)t] = b;
	  if (stats[ip].maxs < b.srcs)
	    stats[ip].maxs = b.srcs;
	}
      return time;
    }
  else
    return 0;
}

void calc_cusum(unsigned int ip, enum type t, struct bcell value, unsigned int time)
{
  stats[ip].statsdata[time].data[t].tag = 0;
  stats[ip].statsdata[time].data[t].rtag = 0;

  for (enum celltype ct = SRC; ct <= RPKTS; ct=(enum celltype)((int)ct+ 1))
    {
      double data;
      if (ct == SRC)
	data = value.srcs;
      else if (ct == VOL)
	data = value.vol;
      else if (ct == PKTS)
	data = value.pkts;
      else if (ct == DST)
	data = value.dsts;
      else if (ct == RVOL)
	data = value.rvol;
      else if (ct == RPKTS)
	data = value.rpkts;

      if(starttime > 0 && (long)time - starttime >= MINS) //metrics[ip][t].stime >= MINS)
	{
	  started = true;
	  long diff = (long)time - starttime;
	  double std = metrics[ip][t].records[ct].stdev;
	  if (std < 1)
	    std = 1;
	  if (ct != SRC && ct != DST && std <= 4096)
	    std = 4096;
	  double tmp = metrics[ip][t].records[ct].cusum*BETA  + (data - metrics[ip][t].records[ct].last)/std;
	    //cout<<"IP "<<toip(ip)<<" ctype "<<t<<" ct "<<ct<<" Calculating cusum time "<<time<<" starttime "<<starttime<<" diff "<<diff<<" old value "<<metrics[ip][t].records[ct].cusum<<" new data "<<data<<" old data "<< metrics[ip][t].records[ct].last<<" std "<<std<<" samples "<<metrics[ip][t].n<<" new value "<<tmp<<endl;
	  metrics[ip][t].records[ct].cusum = tmp;
	  if (tmp > 0)
	    {
	      if (metrics[ip][t].records[ct].cusum > 2*THRESH)
		metrics[ip][t].records[ct].cusum = 2*THRESH;
	    }
	  else
	    {
	      if (metrics[ip][t].records[ct].cusum < -2*THRESH)
		metrics[ip][t].records[ct].cusum = -2*THRESH;
	    }
	}
      if (metrics[ip][t].records[ct].cusum < THRESH)
	metrics[ip][t].records[ct].last = data;
      else
	metrics[ip][t].records[ct].last = metrics[ip][t].records[ct].mean;
      //cout<<"Cusum is "<<metrics[ip][t].records[ct].cusum<<" tag is "<< stats[ip].statsdata[time].data[t].tag<<endl;
      //stats[ip].statsdata[time].data[t].tag += metrics[ip][t].records[ct].cusum;
    }
}

void update_means(unsigned int ip, enum type t, struct bcell value, unsigned int time)  
{
  double diff = -1; // (double)metrics[ip][t].ltime - (double)time;
  double age = pow(2, lambda*diff);
  //cout<<"Ltime "<< metrics[ip][t].ltime<<" time "<<time<<" diff "<<diff<<" age "<<age<<endl;
  // Check if abnormal
  int tag = 0, rtag = 0;

  // First check if there is any anomaly
  for (enum celltype ct = SRC; ct <= RPKTS; ct=(enum celltype)((int)ct+ 1))
    {
      double data;
      if (ct == SRC)
	data = value.srcs;
      else if (ct == VOL)
	data = value.vol;
      else if (ct == PKTS)
	data = value.pkts;
      else if (ct == DST)
	data = value.dsts;
      else if (ct == RVOL)
	data = value.rvol;
      else if (ct == RPKTS)
	data = value.rpkts;

      double std = 0;
      if (metrics[ip][t].records[ct].ss > 0)
	std = metrics[ip][t].records[ct].stdev;
      
      //	cout<<"IP "<<ip<<" time "<<time<<" type "<<t<<" ct "<<ct<<" value "<<data<<" samples "<<metrics[ip][t].n<<" max "<<metrics[ip][t].records[ct].max<<" mean "<<metrics[ip][t].records[ct].mean<<" std "<<std<<" cusum "<< metrics[ip][t].records[ct].cusum;
      if (metrics[ip][t].records[ct].cusum <= THRESH)
	{
	  //cout<<" normal , n is "<<metrics[ip][t].n <<"\n";
	}
      else
	{
	  
	  //cout<<"IP "<<ip<<" time "<<time<<" type "<<t<<" ct "<<ct<<" value "<<data<<" samples "<<metrics[ip][t].n<<" max "<<metrics[ip][t].records[ct].max<<" mean "<<metrics[ip][t].records[ct].mean<<" std "<<std<<" cusum "<< metrics[ip][t].records[ct].cusum;
	  //cout<<" anomalous\n";
	  // Tag as abnormal
	  //cout<<ip<<" "<<t<<" "<<ct<<" anomalous \n";
	  if (ct < DST)
	    tag = tag | (int)pow(2,(int)ct);
	  else
	    rtag = rtag | (int)pow(2,(int)ct - (int)DST);
	  //cout<<"Anomalous ip "<<ip<<" type "<<t<<" measure "<<ct<<" time "<<time<<" cusum "<< metrics[ip][t].records[ct].cusum<<" data "<<data<<endl;
	}
    }
  stats[ip].statsdata[time].data[t].tag = tag;
  stats[ip].statsdata[time].data[t].rtag = rtag;

  //cout<<"IP "<<ip<<" time "<<time<<" type "<<t<<" tag "<<tag<<" rtag "<<rtag<<endl;
  if (tag == 0 && rtag == 0)
    {
      double oldn = metrics[ip][t].n;
      // Age count
      age = 1;
      //cout<<"Updating n from "<<metrics[ip][t].n<<" age "<<age<<" new n ";
      //metrics[ip][t].n *= age;
      metrics[ip][t].n += 1;
      //cout<<metrics[ip][t].n<<" type "<<t<<" srcs "<<value.srcs<<" vol "<<value.vol<<" flows "<<value.flows<<endl;
      for (enum celltype ct = SRC; ct <= RPKTS; ct=(enum celltype)((int)ct+ 1))
	{
	  double data;
	  
	  if (ct == SRC)
	    data = value.srcs;
	  else if (ct == VOL)
	    data = value.vol;
	  else if (ct == PKTS)
	    data = value.pkts;
	  else if (ct == DST)
	    data = value.dsts;
	  else if (ct == RVOL)
	    data = value.rvol;
	  else if (ct == RPKTS)
	    data = value.rpkts;
		
	  if (oldn == 0)
	    {
	      metrics[ip][t].records[ct].mean =  data;
	      metrics[ip][t].records[ct].sum =  data;
	      metrics[ip][t].records[ct].ss = data*data;
	      metrics[ip][t].records[ct].stdev = 0.1;
	    }
	  else
	    {
	      //cout<<"type "<<t<<" ct "<<ct<<" Sum is "<<metrics[ip][t].records[ct].sum<<" aged and added "<<data<<" new sum ";
	      
	      //metrics[ip][t].records[ct].sum *= age;
	      //metrics[ip][t].records[ct].ss *= age;

	      metrics[ip][t].records[ct].sum += data;
	      //cout<<metrics[ip][t].records[ct].sum<<" n is "<<metrics[ip][t].n<<" mean "<<metrics[ip][t].records[ct].mean<<endl;
	      metrics[ip][t].records[ct].ss += data*data;
	      // cout<< metrics[ip][t].records[ct].ss<<endl;

	      
	      metrics[ip][t].records[ct].mean = metrics[ip][t].records[ct].sum/metrics[ip][t].n;
	      double tsum = metrics[ip][t].records[ct].ss/metrics[ip][t].n - pow(metrics[ip][t].records[ct].mean,2);
	      if (tsum <= 0)
		metrics[ip][t].records[ct].stdev = 1;
	      else
		metrics[ip][t].records[ct].stdev = sqrt(tsum);
	    }
	  //cout<<" i "<<t<<" ct "<<ct<<" updated to n "<<metrics[ip][t].n<<" mean "<<metrics[ip][t].records[ct].mean<<" stdev "<<metrics[ip][t].records[ct].stdev<<" ss "<< metrics[ip][t].records[ct].ss<<endl;
	  if (data > metrics[ip][t].records[ct].max)
	    {
	      metrics[ip][t].records[ct].max = data;
	    }	  
	  //cout<<" normal\n";
	}
    }
  metrics[ip][t].ltime = time;      
}

void tag_flows(bool force)
{
  for(auto it = stats.begin(); it != stats.end(); it++)
    {
      unsigned int ip = it->first;
      // See if we need to tag or not
      if ((stats[ip].statsdata.size() < LIMITSIZE && !force) || (stats[ip].statsdata.size() < 10))
	{
	  //cout<<"Skipping "<<toip(ip)<<" samples "<<stats[ip].statsdata.size()<<" force "<<force<<endl;
	  stats[ip].tagged = false;
	  continue;
	}
      stats[ip].tagged = true;
      //cout<<"Tagging "<<toip(ip)<<" samples "<<stats[ip].statsdata.size()<<endl;
      // Initialize
      if (metrics.find(ip) == metrics.end())
	{
	  map<type, record> m;
	  metrics[ip] = m;
	  // Don't tag user def
	  for (enum type t=TOTAL; t<=RPC; t=(enum type)((int)t + 1))
	    {
	      metrics[ip][t].n = 0;
	      metrics[ip][t].ltime = starttime;
	      metrics[ip][t].stime = starttime;
	      for (enum celltype ct = SRC; ct <= RPKTS; ct=(enum celltype)((int)ct+ 1))
		{
		  metrics[ip][t].records[ct].mean = 0;
		  metrics[ip][t].records[ct].ss = 0;
		  metrics[ip][t].records[ct].cusum = 0;
		}
	    }
	}
      // Calculate values
      for (auto iit=stats[ip].statsdata.begin(); iit != stats[ip].statsdata.end(); iit++)
	{
	  unsigned int time = iit->first;
	  cell c = iit->second;

	  for (auto cit = c.data.begin(); cit != c.data.end(); cit++)
	    {
	      enum type t = cit->first;
	      struct bcell value;
	      double age = 0;
	      value.srcs = 0;
	      value.vol = 0;
	      value.pkts = 0;
	      value.dsts = 0;
	      value.rvol = 0;
	      value.rpkts = 0;
	      value = cit->second;
	      
	      //cout<<"\n\nTime "<<time<<" type "<<t<<" srcs "<<value.srcs<<" vol "<<value.vol<<" pkts "<<value.pkts<<endl;
	      calc_cusum(ip, t, value, time);
	      update_means(ip, t, value, time);
	    }
	}
    }
}


// Read from file according to format
void read_from_file(void* nf, char* format, string file_in)
{
  // -1 means EOF, 0 means line without a flow
  char line[MAXLINE];
  double epoch;
  int num_pkts = 0;
  double start = time(0);
  u_char* p;
  struct pcap_pkthdr *h;
  int count = 0;
  // Each million lines tag and print
  while ((epoch = read_one_line(nf, line)) != -1)
    {
      //cout<<"Read "<<saveline<<endl;
      count ++;
      if (count >= 10000000)
	{
	  long diff = (long)endtime - starttime;
	  cout<<"Tagging at time "<<std::fixed<<endtime<<" elapsed "<<diff<<"\n\n";
	  tag_flows(false);
	  print_stats((string)file_in+".tags");
	  count = 0;
	}
    }
  print_stats((string)file_in+".tags");
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
		  if((strcmp(ent->d_name,".") != 0) && (strcmp(ent->d_name,"..") != 0) && (strstr(ent->d_name,"tags") == 0)){
		    inputs.push_back(string(inputs[i]) + "/" + string(ent->d_name));
		    cout<<"Will read "<<ent->d_name<<endl;
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
      cout<<"Considering file "<<file<<" started "<<started<<" startfile "<<(startfile == 0)<<endl;
      if (!started && startfile && strstr(file,startfile) == NULL)
	{
	  continue;
	}
      
      started = 1;
      
      // Now read from file
      char cmd[MAXLINE];
      cout<<"Reading from "<<file<<endl;
      FILE* nf;
      sprintf(cmd,"gunzip -c %s", file);
      nf = popen(cmd, "r");
      read_from_file(nf, format, file);
      if (*vit == tracefiles.back())
	{
	    tag_flows(true);
	    print_stats((string)file_in+".tags");
	}
      stats.clear();
      cout<<"Stats size "<<stats.size()<<" metrics size "<<metrics.size()<<endl;
      sprintf(cmd,"%s.tags", file);
      char* argv[256];
      argv[0] = "gzip";
      argv[1] = cmd;
      argv[2] = NULL;
      int pid = fork();
      if (pid == 0)
	{
	  if (execvp(argv[0], argv) < 0) {  
	    cout<<"Zip failed "<<cmd<<endl;
	    exit(-1);
	  }
	}
      else
	{
	}
      pclose(nf);
    }
  return 0;
}
