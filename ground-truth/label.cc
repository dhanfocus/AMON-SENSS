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
#define DELAY 600
using namespace std;


// Global variables
bool resetrunning = false;
char saveline[MAXLINE];
int numattack = 0;

// We store delimiters in this array
int* delimiters;

string label;

struct bcell {
  set<int> srcs;
  long int vol;
  int asym;
};

enum type {TOTAL, UDPT, ICMPT,  SYNT, ACKT, NTPR, DNSR, FRAG, LDAPR, SYNACKT, RSTT, MDNS, CGEN, L2TP, MCHD, DNS, RPC, USERDEF};

struct cell {
  map<type, bcell> data;
};

map<unsigned int, map<unsigned int, cell>> stats;

// Something like strtok but it doesn't create new
// strings. Instead it replaces delimiters with 0
// in the original string
int parse(char* input, char delimiter, int** array)
{
  int pos = 0;
  memset(*array, 255, AR_LEN);
  int len = strlen(input);
  int found = 0;
  for(int i = 0; i<len; i++)
    {
      if (input[i] == delimiter)
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

// Verbose bit
int verbose = 0;

double firsttime = 0;       // Beginning of trace
double progtime = 0;
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





// Main function, which processes each flow
void
amonProcessing(flow_t flow, int len, double start, double end, int oci, int ooci)
{
  end = (unsigned int) end;
  // Incoming flow
  if (flow.dlocal && !flow.slocal)
    {
      if (stats.find(flow.dst) == stats.end())
	{
	  map<unsigned int, cell> a;
	  stats[flow.dst] = a;
	}
      if (stats[flow.dst].find(end) == stats[flow.dst].end())
	{
	  map<type,bcell> b;
	  stats[flow.dst][end].data = b;
	}
      // Figure out labels
      set<enum type> labels;
      labels.insert(TOTAL);

      // Fragments
      if (flow.sport == 0 && flow.proto != ICMP)
	labels.insert(FRAG);

      // Transport
      if (flow.proto == UDP)
	labels.insert(UDPT);
      else if (flow.proto == ICMP)
	labels.insert(ICMPT);
      else if (flow.flags == 2)
	labels.insert(SYNT);
      else if (flow.flags == 16)
	labels.insert(ACKT);
      else if (flow.flags == 18)
	labels.insert(SYNACKT);
      else if (flow.flags & 4 != 0)
	labels.insert(RSTT);

      // Application
      if (flow.sport == 123)
	labels.insert(NTPR);
      else if (flow.sport == 19)
	labels.insert(CGEN);
      else if (flow.sport == 53)
	labels.insert(DNSR);
      else if (flow.sport == 389)
	labels.insert(LDAPR);
      else if (flow.sport == 5353)
	labels.insert(MDNS);
      else if (flow.sport == 19)
	labels.insert(CGEN);
      else if (flow.sport == 11211)
	labels.insert(MCHD);
      else if (flow.sport == 1701)
	labels.insert(L2TP);
      
      if (flow.dport == 53)
	labels.insert(DNS);
      else if (flow.dport == 111)
	labels.insert(RPC);

      for (auto lit = labels.begin(); lit != labels.end(); lit++)
	{
	  enum type t = *lit;
	  if (stats[flow.dst][end].data.find(t) == stats[flow.dst][end].data.end())
	    {
	      bcell b;
	      b.vol = 0;
	      b.asym = 0;
	      stats[flow.dst][end].data[t] = b;
	    }
	  stats[flow.dst][end].data[t].vol += len;
	  if (t == TOTAL)
	    stats[flow.dst][end].data[t].asym += ooci;
	  else
	    stats[flow.dst][end].data[t].asym += oci;
	  stats[flow.dst][end].data[t].srcs.insert(flow.src);
	}
    }
}


// Update statistics
void update_stats(cell* c)
{

}

	
// Read pcap packet format
void
amonProcessingPcap(u_char* p, struct pcap_pkthdr *h,  double time) // (pcap_pkthdr* hdr, u_char* p, double time)
{
  // Start and end time of a flow are just pkt time
  double start = time;
  double end = time;
  if (end > curtime)
    curtime = end;
  double dur = 1;
  int pkts, bytes;

  struct ip ip;
  // Get source and destination IP and port and protocol 
  flow_t flow;

  struct ether_header ehdr;
  memcpy (&ehdr, p, sizeof (struct ether_header));
  int eth_type = ntohs (ehdr.ether_type);
  if (eth_type == 0x0800)
    {
      memcpy (&ip, p + sizeof (ehdr),sizeof (struct ip));   
      flow.src = ntohl (ip.ip_src.s_addr);
      flow.dst = ntohl (ip.ip_dst.s_addr);
      int proto = ip.ip_p;
      if (proto == IPPROTO_TCP)
	{
	  struct tcphdr *tcp = (struct tcphdr*)(p + sizeof (ehdr) + ip.ip_hl*4);
	  flow.sport = ntohs(tcp->th_sport);
	  flow.dport = ntohs(tcp->th_dport);
	}
      else if (proto == IPPROTO_UDP)
	{
	  struct udphdr *udp = (struct udphdr*)(p + sizeof (ehdr) + ip.ip_hl*4);
	  flow.sport = ntohs(udp->uh_sport);
	  flow.dport = ntohs(udp->uh_dport);
	}
      else
	{
	  flow.sport = 0;
	  flow.dport = 0;
	}
      pkts = 1;
      bytes = ntohs(ip.ip_len);
      flow.slocal = islocal(flow.src);
      flow.dlocal = islocal(flow.dst);
      flow.proto = proto;
      int oci = 1;
      amonProcessing(flow, bytes, start, end, oci, oci); 
    }
}


// Read Flowride flow format
void
amonProcessingFlowride(char* line, double start)
{
  /* 1576613068700777885	ICMP	ACTIVE	x	129.82.138.44	46.167.131.0	0	0	1	0	60	0	0	8	0	1	0	60	0	1576613073700960814 */
  // Line is already parsed
  char send[MAXLINE], rend[MAXLINE];
  strncpy(send, line+delimiters[18],10);
  send[10] = 0;
  strncpy(rend, line+delimiters[18]+10,9);
  rend[9] = 0;
  double end = (double)atoi(send) + (double)atoi(rend)/1000000000;
  if (end > curtime)
    curtime = end;
  double dur = end - start;
  // Normalize duration
  if (dur < 1)
    dur = 1;
  if (dur > 3600)
    dur = 3600;

  // Hack for Flowride
  // assume 5 second interval for reports
  dur = 5;
  
  int pkts, bytes, rpkts, rbytes, pktsdir, pktsrev;

  // Get source and destination IP and port and protocol 
  flow_t flow;
  int proto;
  if (strcmp(line+delimiters[0], "UDP") == 0)
    proto = UDP;
  else if (strcmp(line+delimiters[0], "TCP") == 0)
    proto = TCP;
  else
    proto = 0;

  flow.src = todec(line+delimiters[3]);
  flow.sport = atoi(line+delimiters[5]); 
  flow.dst = todec(line+delimiters[4]);
  flow.dport = atoi(line+delimiters[6]); 
  flow.proto = proto;
  flow.slocal = islocal(flow.src);
  flow.dlocal = islocal(flow.dst);
  int pbytes = atoi(line+delimiters[16]);
  rbytes = atoi(line+delimiters[17]);
  pktsdir = atoi(line+delimiters[14]);
  pktsrev = atoi(line+delimiters[15]);
  // Closed flow, no need to do anything

  if (pktsdir == 0 && pktsrev == 0)
    return;
  processedbytes+=pbytes;

  // Cross-traffic, do nothing
  if (!flow.slocal && !flow.dlocal)
    {
      nl++;
      return;
    }
  l++;
  int flags = atoi(line+delimiters[11]);
  int ppkts = atoi(line+delimiters[14]);
  rpkts = atoi(line+delimiters[15]);
  pkts = (int)(ceil(ppkts/dur));
  bytes = (int)(ceil(pbytes/dur));
  rpkts = (int)(ceil(rpkts/dur));
  rbytes = (int)(ceil(rbytes/dur));

  //if (flow.dst == 2225276007)
  //printf("%lf %lf: FF bytes %d (%d) pkts %d (%d) sport %d dport %d\n", start, end, bytes, pbytes, pkts, ppkts, flow.sport, flow.dport);
  /* Is this outstanding connection? For TCP, connections without 
     PUSH are outstanding. For UDP, connections that have a request
     but not a reply are outstanding. Because bidirectional flows
     may be broken into two unidirectional flows we have values of
     0, -1 and +1 for outstanding connection indicator or oci. For 
     TCP we use 0 (there is a PUSH) or 1 (no PUSH) and for UDP/ICMP we 
     use +1. */
  int oci, roci = 0, ooci = pkts;
  if (proto == TCP)
    {
      // Jelena: Temp ad-hoc fix for Flowride
      // fake a PSH flag for bunch of inc. cases
      if (pkts > 0 && bytes/pkts > 100)
	{
	  flags = flags | 8;
	}
      if (rpkts > 0 && rbytes/rpkts > 100)
	{
	  flags = flags | 8;
	}
      if (flags == 16)
	{
	  flags = flags | 8;
	}
      if ((flags & 1) > 0)
	{
	  flags = flags | 8;
	}
      // There is a PUSH flag
      if ((flags & 8) > 0)
	{
	  oci = 0;
	  roci = 0;
	}
      else
	{
	  oci = pkts;
	  roci = rpkts;
	}
    }
  else if (proto == UDP)
    {
      oci = pkts;
      roci = rpkts;
    }
  else
    // unknown proto
    {
      oci = pkts;
      roci = rpkts;
    }
  // Don't deal with TCP flows w PUSH flags // Jelena should say "unless they have RST flags"
  if (oci == 0)
    return;
  //cout<<"Start "<<start<<" end "<<end<<" dur "<<dur<<" bytes "<<bytes<<" oci "<<oci<<" line "<<saveline<<" flags "<<flags<<endl; // Jelena
  amonProcessing(flow, bytes, start, end, oci, ooci);
}

// Read nfdump flow format
void amonProcessingNfdump (char* line, double time)
{
  /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
  // Get start and end time of a flow
  char* tokene;
  strcpy(saveline, line);
  parse(line,'|', &delimiters);
  double start = (double)strtol(line+delimiters[0], &tokene, 10);
  start = start + strtol(line+delimiters[1], &tokene, 10)/1000.0;
  double end = (double)strtol(line+delimiters[2], &tokene, 10);
  end = end + strtol(line+delimiters[3], &tokene, 10)/1000.0;
  if (end > curtime)
    curtime = end;
  double dur = end - start;
  // Normalize duration
  if (dur < 0)
    dur = 0;
  if (dur > 3600)
    dur = 3600;
  int pkts, bytes;

  // Get source and destination IP and port and protocol 
  flow_t flow;
  int proto = atoi(line+delimiters[4]);
  flow.src = strtol(line+delimiters[8], &tokene, 10);
  flow.sport = atoi(line+delimiters[9]); 
  flow.dst = strtol(line+delimiters[13], &tokene, 10);
  flow.dport = atoi(line+delimiters[14]); 
  flow.proto = proto;
  int flags = atoi(line+delimiters[19]);
  flow.flags = flags;
  flow.slocal = islocal(flow.src);
  flow.dlocal = islocal(flow.dst);
  bytes = atoi(line+delimiters[22]);
  processedbytes+=bytes;

  // Cross-traffic, do nothing
  if (!flow.slocal && !flow.dlocal)
    {
      nl++;
      return;
    }
  l++;

  pkts = atoi(line+delimiters[21]);
  int ooci = pkts;
  //cout<<std::fixed<<"Jelena "<<start<<" "<<end<<" "<<pkts<<" "<<bytes<<endl;
  /* Is this outstanding connection? For TCP, connections without 
     PUSH are outstanding. For UDP, connections that have a request
     but not a reply are outstanding. Because bidirectional flows
     may be broken into two unidirectional flows we have values of
     0, -1 and +1 for outstanding connection indicator or oci. For 
     TCP we use 0 (there is a PUSH) or 1 (no PUSH) and for UDP/ICMP we 
     use +1 for requests and -1 for replies. */
  int oci;
  if (proto == TCP)
    {
      // There is a PUSH flag or just ACK
      if ((flags & 8) > 0 || (flags == 16)) 
	oci = 0;
      else
	oci = pkts;
    }
  else if (proto == UDP || proto == ICMP)
    {
      oci = pkts;
    }
  else
    return;
  
  if (oci == 0)
    return;

  amonProcessing(flow, bytes, start, end, oci, ooci); 
}




// Print help for the program
void
printHelp (void)
{
  printf ("amon-senss\n(C) 2018 University of Southern California.\n\n");

  printf ("-h                             Print this help\n");
  printf ("-r <file|folder|iface>         Input is in given file or folder, or live on the specified iface\n");
  printf ("-F <pcap|plive|ft|nf|fr>       Input is in this format\n");
  printf ("\t pcap - libpcap format in a file\n");
  printf ("\t plive - libpcap live read from interface\n");
  printf ("\t ft - flowtools format in a file\n");
  printf ("\t nf - netflow format in a file\n");
  printf ("\t fr - Flowride format in a file\n");
  printf ("-s <file>                      Start from this given file in the input folder\n");
  printf ("-e <file>                      End with this given file in the input folder\n");
  printf ("-v                             Verbose\n");
}



// Define the function to be called when ctrl-c (SIGINT) is sent to process
void signal_callback_handler(int signum) {
   cout << "Caught signal " << signum << endl;
   // Terminate program
   exit(signum);
}

// Read one line from file according to format
double read_one_line(void* nf, char* format, char* line, u_char* p,  struct pcap_pkthdr *h)
{
  if (!strcmp(format, "nf") || !strcmp(format, "ft") || !strcmp(format,"fr"))
    {
      char* s = fgets(line, MAXLINE, (FILE*) nf);
      char* tokene;
      if (s == NULL)
	return -1;

      char tmpline[MAXLINE];
      strcpy(tmpline, line);
      if (!strcmp(format, "nf") || !strcmp(format, "ft"))
	{
	  if (strstr(tmpline, "|") == NULL)
	    return 0;
	  int dl = parse(tmpline,'|', &delimiters);

	  double start = (double)strtol(tmpline+delimiters[0], &tokene, 10);
	  start = start + strtol(tmpline+delimiters[1], &tokene, 10)/1000.0;
	  double end = (double)strtol(tmpline+delimiters[2], &tokene, 10);
	  end = end + strtol(tmpline+delimiters[3], &tokene, 10)/1000.0;
	  return end;
	}
      else {
	int dl = parse(line,'\t', &delimiters);
	if (dl != 19)
	  return 0;
	
	char sstart[MAXLINE], rstart[MAXLINE];
	strncpy(sstart, line+delimiters[18],10);
	sstart[10] = 0;
	strncpy(rstart, line+delimiters[18]+10,9);
	rstart[9] = 0;
	double epoch = (double)atoi(sstart)+(double)atoi(rstart)/1000000000;
	return epoch;
      }
    }
  else if (!strcmp(format,"pcap") || !strcmp(format,"plive"))
    {
      int rc = pcap_next_ex((pcap_t*)nf, &h, (const u_char **) &p);
      if (rc <= 0)
	return 0;
      struct ether_header* eth_header = (struct ether_header *) p;
      
      if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) 
	return 0;
      double epoch = h->ts.tv_sec + h->ts.tv_usec/1000000.0;
      return epoch;
    }
  //Jelena add more formats
  return 0;
}

void process_one_line(char* line, void* nf, double epoch, char* format, u_char* p, struct pcap_pkthdr *h)
{
  if (!strcmp(format, "nf") || !strcmp(format, "ft"))
    amonProcessingNfdump (line, epoch);
  else if (!strcmp(format, "fr"))
    amonProcessingFlowride (line, epoch);
  else if (!strcmp(format, "pcap"))
    amonProcessingPcap(p, h, epoch);
  // add more formats
}

//  Print out stats
void print_stats(double epoch, bool force)
{
  ofstream out;
  out.open("output.txt", std::ios_base::app);
  int i = 0;
  for(auto it = stats.begin(); it != stats.end(); it++)
    {
      for (auto iit = it->second.begin(); iit != it->second.end();)
	{
	  if (iit->first + DELAY < epoch || force)
	    {
	      out<<toip(it->first)<<" "<<iit->first<<" ";
	      for (auto dit = iit->second.data.begin(); dit != iit->second.data.end(); dit++)
		{
		  out<<dit->first<<" "<<dit->second.srcs.size()<<" "<<dit->second.vol<<" "<<dit->second.asym<<",";
		}
	      out<<endl;
	      auto dit = iit;
	      iit++;
	      it->second.erase(dit);
	    }
	  else
	    iit++;	  
	}
    }
  if (force)
    stats.clear();
  out.close();
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
  while ((epoch = read_one_line(nf, format, line, p, h)) != -1)
    {
      if (epoch == 0)
	continue;
      if (firsttime == 0)
	{
	  firsttime = epoch;
	  progtime = epoch;
	}
      num_pkts++;
      if (firsttimeinfile == 0)
	firsttimeinfile = epoch;
      allflows++;
      if (allflows % 1000000 == 0)
	{
	  double diff = time(0) - start;
	  double ttime = epoch - progtime;
	  cout<<"Processed "<<allflows<<", 1M in "<<diff<<" trace time "<<ttime<<" size "<<stats.size()<<endl;
	  print_stats(epoch, false);
	  start = time(0);
	}
      processedflows++;
      process_one_line(line, nf, epoch, format, p, h);
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
  
  while ((c = getopt (argc, argv, "hvr:s:e:F:")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'h':
	  printHelp ();
	  return (0);
	  break;
	case 'F':
	  format = strdup(optarg);
	  if (strcmp(format,"pcap") && strcmp(format,"plive") && strcmp(format,"ft") && strcmp(format,"nf") && strcmp(format,"fr"))
	    {
	      cerr<<"Unknown format "<<format<<endl;
	      exit(1);
	    }
	  break;
	case 'r':
	  file_in = strdup(optarg);
	  label = file_in;
	  break;
	case 's':
	  startfile = strdup(optarg);
	  cout<<"Start file "<<startfile<<endl;
	  break;
	case 'e':
	  endfile = strdup(optarg);
	  cout<<"End file "<<endfile<<endl;
	  break;
	case 'v':
	  verbose = 1;
	  break;
	}
    }
  if (file_in == NULL && stream_in == 0)
    {
      cerr<<"You must specify an input folder, which holds Netflow records\n";
      exit(-1);
    }
  cout<<"Verbose "<<verbose<<endl;
  loadprefixes("localprefs.txt");
  signal(SIGINT, signal_callback_handler);

  clock_gettime(CLOCK_MONOTONIC, &last_entry);      
  // This is going to be a pointer to input
  // stream, either from nfdump or flow-tools */
  FILE* nf, * ft;
  unsigned long long num_pkts = 0;      

  // Read flows from a file
  if (stream_in)
    {
      read_from_file(stdin, format);
    }
  else 
    {
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
      cout<<"Format is "<<format<<endl;
      for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
      {
	const char* file = vit->c_str();

	if (!started && startfile && strstr(file,startfile) == NULL)
	  {
	    continue;
	  }

	started = 1;

	// Now read from file
	char cmd[MAXLINE];
	cout<<"Reading from "<<file<<endl;
	firsttimeinfile = 0;

	if (!strcmp(format, "pcap") || !strcmp(format, "plive"))
	  {
	    char ebuf[MAXLINE];
	    pcap_t *pt;
	    if (is_live)
	      pt = pcap_open_live(file, MAXLINE, 1, 1000, ebuf);
	    else
	      pt = pcap_open_offline (file, ebuf);
	    read_from_file(pt, format);
	  }
	else
	  {
	    if (!strcmp(format, "nf"))
	      {
		sprintf(cmd,"nfdump -r %s -o pipe 2>/dev/null", file);
	      }
	    else if (!strcmp(format, "ft"))
	      {
		sprintf(cmd,"ft2nfdump -r %s | nfdump -r - -o pipe", file);
	      }
	    else if (!strcmp(format, "fr"))
	      {
		sprintf(cmd,"gunzip -c %s", file);
	      }
	    nf = popen(cmd, "r");
	    read_from_file(nf, format);
	    pclose(nf);
	  }
	cout<<"Done with the file "<<file<<" time "<<time(0)<<" flows "<<allflows<<endl;
	// Print out stats
	if (endfile && strstr(file,endfile) != 0)
	  {
	    print_stats(curtime, true);
	    break;
	  }
      }
    }
  return 0;
}
