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


// Limits
#include<bits/stdc++.h> 

#include "utils.h"


#define BILLION 1000000000L
#define DAY 86400
using namespace std;


// Global variables
bool resetrunning = false;
char saveline[MAXLINE];
int numattack = 0;

// We store delimiters in this array
int* delimiters;


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

// Variables/structs needed for detection
struct cell
{
  long int databrick_p[BRICK_DIMENSION];	 // databrick volume
  long int databrick_s[BRICK_DIMENSION];         // databrick symmetry 
  unsigned int wfilter_p[BRICK_DIMENSION];	 // volume w filter 
  int wfilter_s[BRICK_DIMENSION];	         // symmetry w filter 
};

// Should we require destination prefix
bool noorphan = false;
// How many service ports are there
int numservices = 0;
// Save all flows for a given time slot
map<long, time_flow*> timeflows;

// These are the bins where we store stats
cell cells[QSIZE];
int cfront = 0;
int crear = 0;
bool cempty = true;

// Samples of flows for signatures
sample samples;

// Signatures per bin
stat_r signatures[BRICK_DIMENSION];
// Is the bin abnormal or not
int is_abnormal[BRICK_DIMENSION];
// Did we detect an attack in this bin
int is_attack[BRICK_DIMENSION];
// When we detected the attack
unsigned long detection_time[BRICK_DIMENSION];
// Are we simulating filtering. 
bool sim_filter = false;

// Did we complete training
bool training_done = false;
int trained = 0;

// Current time
double curtime = 0;
double lasttime = 0;
double lastlogtime = 0;
double lastbintime = 0;

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

// Serialize access to statistics
pthread_mutex_t cells_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t samples_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cnt_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rst_lock = PTHREAD_MUTEX_INITIALIZER;

// Types of statistics. If this changes, update the entire section 
enum period{cur, hist};
enum type{n, avg, ss};
enum dim{vol, sym};
double stats[2][3][2][BRICK_DIMENSION]; // historical and current stats for attack detection
double cusum[2][BRICK_DIMENSION];
string label;

// Parameters from as.config
map<string,double> parms;
map<string,string> sparms;



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

// Parse configuration file and load into parms
void
parse_config(map <string,double>& parms, map <string,string>& sparms)
{
  char *s, buff[256];
  FILE *fp = fopen ("as.config", "r");
  if (fp == NULL)
  {
    cout <<"Config file as.config does not exist. Please include it and re-run.. \n";
    exit (0);
  }
  cout << "Reading config file as.config ...";
  while ((
	  s = fgets (buff, sizeof buff, fp)) != NULL)
  {
        // Skip blank lines and comment lines 
        if (buff[0] == '\n' || buff[0] == '#')
          continue;

	// Look for = sign and abort if that does not
	// exist
	char name[MAXLINE], value[MAXLINE];
	int found = -1;
	int i = 0;
	for(i=0; i<strlen(buff); i++)
	  {
	    if (buff[i] == '=')
	      {
		strncpy(name,buff, i);
		name[i] = 0;
		found = i;
	      }
	    else if((buff[i] == ' ' || buff[i] == '\n') && found >= 0)
	      {
		strncpy(value,buff+found+1,i-found-1);
		value[i-found-1] = 0;
		break;
	      }
	  }
	if (i > 0 && found > -1)
	  {
	    strncpy(value,buff+found+1,i-found-1);
	    value[i-found-1] = 0;
	  }
	if (found == -1)
	  continue;
	trim(name);
	trim(value);
	cout<<"Parm "<<name<<" val "<<value<<endl;
	if (!strcmp(name,"logs") || !strcmp(name,"evids"))
	  sparms.insert(pair<string,string>(name, value));
	else
	  parms.insert(pair<string,double>(name,strtod(value,0)));
  }
  fclose (fp);
}


// Check if the signature is subset or matches
// exactly the slot where anomaly was found.
// For example, if a source port's traffic was
// anomalous we have to have that source port in the
// signature
bool compliantsig(int i, flow_t sig)
{
  switch (i/BRICK_UNIT)
    {
    case 0:
    case 1:
      return (sig.dst != 0 && (sig.dport != -1 || sig.sport != -1 || sig.proto == ICMP));
    case 2:
    case 4:
    case 5:
      return (sig.dst != 0 && (sig.sport != -1|| sig.proto == ICMP));
    case 3:
    case 6:
    case 7:
      return (sig.dst != 0 && (sig.dport != -1 || sig.proto == ICMP));
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
      return (sig.dst != 0 && sig.flags != 0);
    default:
      return false;
    }
}


void clearSamples(int index)
{
  flow_t key;
  pthread_mutex_lock(&samples_lock);
  for (int s=1; s<NF; s++)
    {
      samples.bins[index].flows[s].flow = key;
      samples.bins[index].flows[s].len = 0;
      samples.bins[index].flows[s].oci = 0;
    }
  pthread_mutex_unlock(&samples_lock);
}

// Add a flow to the samples bin
void addSample(int index, flow_p* f, int way)
{
  // Create some partial signatures for this flow, like src-dst combination,
  // src-sport, etc. Don't allow just protocol
  // Don't add samples for flags separately since they are already going
  // to separate bins
  for (int s=1; s<NF-8; s++)
    {
      pthread_mutex_lock(&samples_lock);
      
      flow_t k;
      k.proto = f->flow.proto;
      if ((s & 8) > 0) // Jelena
	k.src = f->flow.src;
      if ((s & 4) > 0 && isservice(f->flow.sport))
	k.sport = f->flow.sport;
      if ((s & 2) > 0)
	k.dst = f->flow.dst;
      if ((s & 1) > 0 && isservice(f->flow.dport))
	k.dport = f->flow.dport;
      //if (index == 3493)
      //cout<<"s="<<s<<printsignature(k)<<" sport "<<f->flow.sport<<endl;
      if (way == LHOST || way == LPREF || way == LHFPORT || way == LHLPORT || way == LPFPORT || way == LPLPORT || way == LHSYN || way == LPSYN || way == LHSYNACK || way == LPSYNACK || way == LHRST || way == LPRST)
	{
	  k.dst = f->flow.dst;
	  if (way == LPREF || way == LPFPORT || way == LPLPORT || way == LPSYN || way == LPSYNACK || way == LPRST)
	    k.dst &= 0xffffff00;
	}
      if (way == FPORT || way == LHFPORT || way == LPFPORT)
	k.sport = f->flow.sport;
      if (way == LPORT || way == LHLPORT || way == LPLPORT) 
	k.dport = f->flow.dport;
      if (way >= LHSYN)
	k.flags = f->flow.flags;
      
      //if (index == 12205)
      //cout<<"Add sample oci "<<f->oci<<" sig "<<printsignature(k)<<" way "<<way<<" s="<<s<<" current "<<printsignature(samples.bins[index].flows[s].flow)<<" len "<<samples.bins[index].flows[s].len<<" line "<<saveline<<" is attack "<<is_attack[index]<<endl;
      // src, dst, sport, dport
      // Overload len so we can track frequency of contributions
      // Jelena - there was continue here
      // Insert sample if it does not exist
      if (samples.bins[index].flows[s].flow == k)
	{
	  // Else increase contributions of this signature wrt symmetry
	  samples.bins[index].flows[s].len += abs(f->oci);
	  samples.bins[index].flows[s].oci += f->oci;
	  // if (index == 12205)
	  //cout<<"Added sample, now the len is "<<samples.bins[index].flows[s].len<<" we added "<<abs(f->oci)<<" line "<<saveline;
	}
      else	
	{
	  // Boyer Moore to find signatures that cover the most flows
	  if (empty(samples.bins[index].flows[s].flow))
	    {
	      // if (index == 12205)
	      //cout<<"Added initial sample\n";
	      samples.bins[index].flows[s].flow = k;
	      samples.bins[index].flows[s].len = abs(f->oci);
	      samples.bins[index].flows[s].oci = f->oci;
	    }
	  else
	    {
	      int olen = samples.bins[index].flows[s].len;
	      samples.bins[index].flows[s].len -= abs(f->oci);
	      int nlen = samples.bins[index].flows[s].len;
	      //if (index == 12205)
	      //	cout<<"Added sample, now the len is "<<samples.bins[index].flows[s].len<<" old len "<<olen<<" new len "<<nlen<<" we removed "<<abs(f->oci)<<" line "<<saveline;
	      // Replace this signature if there's another one,
	      // which covers more
	      if (samples.bins[index].flows[s].len < 0)
		{
		  samples.bins[index].flows[s].flow = k;
		  samples.bins[index].flows[s].len = abs(f->oci);
		  samples.bins[index].flows[s].oci = f->oci;
		}
	    }
	}
      //if (index == 9800)
      //cout<<"Add sample, now the len is "<<samples.bins[index].flows[s].len<<" and sig "<<printsignature(samples.bins[index].flows[s].flow)<<endl;
      pthread_mutex_unlock(&samples_lock);
    }
} 


// Does this flow match the given signature
int match(flow_t flow, flow_t sig)
{
  if (flow.proto != sig.proto && sig.proto != 0)
    {
      return 0;
    }
  if (empty(sig))
    {
      return 0;
    }
  if ((flow.src == sig.src || sig.src == 0) &&
      (flow.sport == sig.sport || sig.sport == -1) &&
      (flow.dst == sig.dst || sig.dst == 0) &&
      (flow.dport == sig.dport || sig.dport == -1) &&
      ((flow.flags & sig.flags) > 0 || sig.flags == 0))
    {
      return 1;
    }
  else
    {
      return 0;
    }
}

// Is this timestamp within the range, which we expect in a given input file
int malformed(double timestamp)
{
  // Give some space here in case we're a few ms off
  if (timestamp < firsttimeinfile-1 || (parms["file_interval"] > 0 && timestamp > firsttimeinfile +
				      parms["file_interval"]))
    {
      //cout<<"Malformed "<<timestamp<<" first time "<<firsttimeinfile-1<<endl;
      return 1;
    }
  return 0;
}

// Function to detect values higher than mean + parms[num_std] * stdev 
double abnormal(int type, int index, cell* c)
{
  // Look up std and mean
  double mean = stats[hist][avg][type][index];
  double std = sqrt(stats[hist][ss][type][index]/
		    (stats[hist][n][type][index]-1));
  // Look up current value
  int data;
  if (type == vol)
    data = c->databrick_p[index];
  else
    data = c->databrick_s[index];
  // If we don't have enough samples return 0
  if (stats[hist][n][type][index] <
      parms["min_train"]*MIN_SAMPLES)
    return 0;

  // calculate cusum
  double tmp = cusum[type][index] + data - mean - 3*std;
  if (tmp < 0)
    tmp = 0;
  
  double rto = tmp/(std+1);

  //if (index == 13207)
  //cout<<curtime<<" Cusum for type "<<type<<" data "<<data<<" mean "<<mean<<" std "<<std<<" is "<<cusum[type][index]<<" rto "<<rto<<endl;
  
  if (rto > 0)
    return rto;
  else
    return 0;
  /* Volume larger than mean + num_std*stdev is abnormal 
  if (data > mean + parms["num_std"]*std)
    {
      return 1;
    }
  else
    {
      return 0;
    }
  */
}

// Print alert into the alerts file
void print_alert(int i, cell* c, int na)
{
  double diff = curtime - lasttime;
  if (diff < 1)
    diff = 1;
  double avgv = stats[hist][avg][vol][i];
  double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
  double avgs = stats[hist][avg][sym][i];
  double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));
  long int rate = c->databrick_p[i] - avgv - parms["num_std"]*stdv;
  long int roci = c->databrick_s[i] - avgs - parms["num_std"]*stds;
  
  // Write the start of the attack into alerts
  ofstream out;
  
  if (abs(roci) < parms["min_oci"])
    return;
  
  pthread_mutex_lock(&cnt_lock);
  
  out.open("alerts.txt", std::ios_base::app);
  out<<na<<" "<<i/BRICK_UNIT<<" "<<(long)curtime<<" ";
  out<<"START "<<i<<" "<<abs(rate);
  out<<" "<<abs(roci)<<" ";
  out<<printsignature(signatures[i].sig)<<endl;
  out.close();
  
  // Save evidence of attack
  if (false)  // Jelena put back
    {
      char filename[MAXLINE];
      sprintf(filename, "%s/attack%d", sparms["evids"].c_str(), na);
      out.open(filename, std::ios_base::app);
      for (int j=0; j < signatures[i].nm; j++)
	out<<signatures[i].matches[j];
      out.close();
    }
  pthread_mutex_unlock(&cnt_lock);
  
  // Check if we should rotate file
  ifstream in("alerts.txt", std::ifstream::ate | std::ifstream::binary);
  if (in.tellg() > 10000000)
    {
      system("./rotate");
    }
}

void alert_ready(cell* c, int bucket)
{
  double volf = c->wfilter_p[bucket];
  double volb = c->databrick_p[bucket];
  if (volb == 0)
    volb = 1;
  double avgs = stats[hist][avg][sym][bucket];
  double stds = sqrt(stats[hist][ss][sym][bucket]/(stats[hist][n][sym][bucket]-1));
  double symf = abs(c->wfilter_s[bucket]);
  double symb = abs(c->databrick_s[bucket]) - (abs(avgs) + parms["num_std"]*abs(stds));
  if (symb < 0)
    symb = symf;
  double data = abs(c->databrick_s[bucket]);
  if (symb == 0)
    symb = 1;
  if (symf/symb >= parms["filter_thresh"]) // && abnormal(vol,bucket,c) && abnormal(sym,bucket,c))
    {
      pthread_mutex_lock(&cnt_lock);
      int na = numattack++;
      pthread_mutex_unlock(&cnt_lock);
      cout<<curtime<<" event "<<na<<" Signature works for "<<bucket<<" wfilter "<<symf<<","<<volf<<" without "<<symb<<","<<volb<<" stored matches "<<signatures[bucket].nm<<printsignature(signatures[bucket].sig)<<endl;
      print_alert(bucket, c, na);
    }
  else
    {
      cout<<curtime<<" matched enough for "<<bucket<<" but failed to filter enough, filtered "<<symf<<" out of "<<symb<<" abnormals "<<abnormal(vol,bucket,c)<<" and "<<abnormal(sym,bucket,c)<<" avgs "<<avgs<<" stds "<<stds<<" data "<<data<<endl;
    }
  is_attack[bucket] = false;
  detection_time[bucket] = 0;
  clearSamples(bucket);
}

void checkReady(int bucket, cell* c)
{
  
  if (signatures[bucket].nm < MM)
    {
      strcpy(signatures[bucket].matches[signatures[bucket].nm++], saveline);
      cout<<"Matches for bucket "<<bucket<<" "<<signatures[bucket].nm<<endl;
      if (signatures[bucket].nm == MM)
	{
	  alert_ready(c, bucket);
	}
    }
}

// Should we filter this flow?
bool shouldFilter(int bucket, flow_t flow, cell* c)
{
  if (!empty(signatures[bucket].sig) && match(flow,signatures[bucket].sig))
    return true;
  else
    return false;
}

long votedtime = 0;
int votes = 0;
const int MINVOTES = 1; // usually at 5 but for Flowride we set it to 1

void findBestSignature(double curtime, int i, cell* c)
{
  flow_t bestsig;
  int oci = 0;
  int maxoci = 0;
  double avgs = stats[hist][avg][sym][i];
  double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));
  int totoci = abs(c->databrick_s[i]) - abs(avgs) -  parms["num_std"]*abs(stds); 
  
  // Go through candidate signatures
  for (int s=1; s<NF; s++)
    {
      if (empty(samples.bins[i].flows[s].flow))
	continue;

      double candrate = abs((double)samples.bins[i].flows[s].oci);

      if (!compliantsig(i, samples.bins[i].flows[s].flow))
	{
	  if (verbose)
	    cout<<"non compliant SIG: "<<i<<" for slot "<<s<<" candidate "<<printsignature(samples.bins[i].flows[s].flow)<<" v="<<samples.bins[i].flows[s].len<<" o="<<samples.bins[i].flows[s].oci<<" toto="<<totoci<<" candrate "<<candrate<<" divided "<<candrate/totoci<<endl;
	    continue;
	}

      // Print out each signature for debugging
      if (verbose)
	cout<<"SIG: "<<i<<" for slot "<<s<<" candidate "<<printsignature(samples.bins[i].flows[s].flow)<<" v="<<samples.bins[i].flows[s].len<<" o="<<samples.bins[i].flows[s].oci<<" toto="<<totoci<<" candrate "<<candrate<<" divided "<<candrate/totoci<<endl;
      // Potential candidate
      if (candrate/totoci > parms["filter_thresh"])
	{
	  // Is it a more specific signature?
	  if (bettersig(samples.bins[i].flows[s].flow, bestsig))
	    {
	      if (verbose)
		cout<<"SIG: changing to "<< printsignature(samples.bins[i].flows[s].flow)<<endl;
	      bestsig = samples.bins[i].flows[s].flow;
	      oci = candrate;
	    }
	}
    }
  if (verbose)
    cout<<"SIG: "<<i<<" best sig "<<printsignature(bestsig)<<" Empty? "<<empty(bestsig)<<" oci "<<maxoci<<" out of "<<totoci<<endl;
  // Remember the signature if it is not empty and can filter
  // at least filter_thresh flows in the sample
  if (!empty(bestsig))
    {
      if (verbose)
	cout<<curtime<<" ISIG: "<<i<<" volume "<<c->databrick_p[i]<<" oci "<<c->databrick_s[i]<<" installed sig "<<printsignature(bestsig)<<endl;

      // insert signature and reset all the stats
      if (sim_filter)
	{
	  if(verbose)
	    cout<<"Sim filter is on"<<endl;
	  
	  signatures[i].sig = bestsig;
	  signatures[i].vol = 0;
	  signatures[i].oci = 0;
	  signatures[i].nm = 0;	  
	}
      
      // Now remove abnormal measure and samples, we're done
      // Leave some measure of abnormal so we don't go ahead and
      // update statistics
      //is_abnormal[i] = 1;
      // Clear samples
      clearSamples(i);
      // Clear attack detection time
      //detection_time[i] = 0;
    }
  // Did not find a good signature
  // drop the attack signal and try again later
  else
    {
      if (verbose)
	cout << "AT: Did not find good signature for attack "<<
	  " on bin "<<i<<" best sig "<<empty(bestsig)<<
	  " coverage "<<(float)oci/totoci<<" thresh "<<
	  parms["filter_thresh"]<<endl;
      is_attack[i] = false;
    }
}

void instant_detect(cell* c, double ltime, int i)
{
  double avgv = stats[hist][avg][vol][i];
  double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
  double avgs = stats[hist][avg][sym][i];
  double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));
  int volume = c->databrick_p[i];
  int asym = c->databrick_s[i];
  
  if (!is_attack[i])
    {
      // If both volume and asymmetry are abnormal and training has completed
      double a = abnormal(vol, i, c);
      double b = abnormal(sym, i, c);
      int volume = c->databrick_p[i];
      int asym = c->databrick_s[i];

      if (training_done && abnormal(vol, i, c) && abnormal(sym, i, c))
	{
	  double aavgs = abs(avgs);
	  if (aavgs == 0)
	    aavgs = 1;
	  double d = abs(abs(asym) - abs(avgs) - parms["num_std"]*abs(stds))/aavgs;
	  if (d > parms["max_oci"])
	    d = parms["max_oci"];
	  
	  if (a >= parms["cusum_thresh"] && b >= parms["cusum_thresh"])
	    is_abnormal[i] = int(parms["attack_high"]);
	  else
	    {
	      is_abnormal[i] = a+b;
	      if (is_abnormal[i] > int(parms["attack_high"]))
		is_abnormal[i] = int(parms["attack_high"]); //Jelena used to be /2
	    }
	  /*			 
	  // Increase abnormal score, but cap at attack_high
	  if (is_abnormal[i] < int(parms["attack_high"]))
	  is_abnormal[i] += int(d+1);
	  if (is_abnormal[i] > int(parms["attack_high"]))
	  is_abnormal[i] = int(parms["attack_high"]);
	  */
	  
	  if (verbose)
	    cout<<ltime<<" abnormal for "<<i<<" points "<<is_abnormal[i]<<" oci "<<c->databrick_s[i]<<" ranges " <<avgs<<"+-"<<stds<<", vol "<<c->databrick_p[i]<<" ranges " <<avgv<<"+-"<<stdv<<" over mean "<<d<<" a "<<a<<" b "<<b<<" cusum thresh " << parms["cusum_thresh"]<<endl;

	  // If abnormal score is above attack_low
	  // and oci is above MAX_OCI
	  if (is_abnormal[i] >= int(parms["attack_low"])
	      && !is_attack[i] && abs(c->databrick_s[i]) >= int(parms["max_oci"]))
	    {
	      // Signal attack detection 
	      is_attack[i] = true;
	      detection_time[i] = ltime;
	      if (verbose)
		cout<<"AT: Attack detected on "<<i<<" but not reported yet vol "<<c->databrick_p[i]<<" oci "<<c->databrick_s[i]<<" max oci "<<int(parms["max_oci"])<<endl;
	      
	      // Find the best signature
	      findBestSignature(ltime, i, c);
	    }
	}
    }
}


// Main function, which processes each flow
void
amonProcessing(flow_t flow, int len, double start, double end, int oci)
{
  // Detect if the flow is malformed and reject it
  if (malformed(end))
    {
      mal++;
      cout<<"Malformed "<<start<<" end "<<end<<endl;
      return;
    }
  // Detect if it is UDP for port 443 or 4500 or 4501
  // and reject it
  if (flow.sport == 443 || flow.dport == 443 || flow.sport == 4500 || flow.dport == 4500 || flow.sport == 4501 || flow.dport == 4501)
    return;
  
  if (flow.proto == ICMP)
    {
      flow.sport = -2;
      flow.dport = -2;
    }
  //cout<<"Flow from "<<flow.src<<":"<<flow.sport<<"->"<<flow.dst<<":"<<flow.dport<<endl;
  // Standardize time
  if (curtime == 0)
    curtime = end;
  if ((unsigned long)end > (unsigned long)curtime)
    {
      if (votes == 0)
	votedtime = (int)end;
      if ((int)end == votedtime)
	votes++;
      else
	votes--;
      if (votes >= MINVOTES)
	{
	  curtime = end;
	  votedtime = 0;
	  votes = 0;
	}
    }

  if (lasttime == 0)
    lasttime = curtime;

  flow_p fp(start, end, len, oci, flow);
      
  int d_bucket = -1, s_bucket = -1;	    // indices for the databrick 

  cell *c = &cells[crear];

  int is_filtered = false;

  if (sim_filter)
    {
      for (int way = LHOST; way <= LPRST; way++) // SERV is included in CLI
	{
	  // Find buckets on which to work
	  if (way == LHOST || way == LPREF || way >= LHSYN)
	    {
	      if (flow.dlocal)
		{
		  d_bucket = myhash(flow.dst, 0, way);
		  if (shouldFilter(d_bucket, flow, c))
		    {
		      is_filtered = true;
		      c->wfilter_p[d_bucket] += len;
		      c->wfilter_s[d_bucket] += oci;
		      checkReady(d_bucket,c);
		      //if (d_bucket == 3493)
		      //cout<<"Match filtering "<<printsignature(flow)<<" len "<<len<<" oci "<<oci<<" filtered "<<c->wfilter_p[d_bucket]<<" "<< c->wfilter_s[s_bucket]<<" start "<<start<<" end "<<end<<endl;
		    }
		  else
		    {
		      //if (d_bucket == 3493)
		      //cout<<"Match not filtering "<<printsignature(flow)<<" start "<<start<<" end "<<end<<" score "<<is_abnormal[d_bucket]<<" oci "<<c->databrick_s[d_bucket]<<endl;
		    }
		}
	    }
	  else if (way == FPORT) 
	    {
	      if (flow.dlocal)
		{
		  // traffic from FPORT
		  s_bucket = myhash(0, flow.sport, way);
		  if (shouldFilter(s_bucket, flow, c))
		    {
		      is_filtered = true;
		      c->wfilter_p[s_bucket] += len;
		      c->wfilter_s[s_bucket] += oci;
		      checkReady(s_bucket,c);
		    }
		}
	    }
	  else if (way == LPORT)
	    {
	      if (flow.dlocal)
		{
		  // traffic to LPORT
		  d_bucket = myhash(0, flow.dport, way);
		  if (shouldFilter(d_bucket, flow, c))
		    {
		      is_filtered = true;
		      c->wfilter_p[d_bucket] += len;
		      c->wfilter_s[d_bucket] += oci;
		      checkReady(d_bucket,c);
		    }
		}
	    }
	  else if (way == LHFPORT || way == LPFPORT || way == LHLPORT || way == LHFPORT)
	    {
	      if (flow.dlocal)
		{
		  short port;
		  if (way == LHFPORT || way == LPFPORT)
		    port = flow.sport;
		  else
		    port = flow.dport;
		  d_bucket = myhash(flow.dst, port, way);
		  if (flow.dst == 2197625602)
		    printf("%lf %lf: flow bytes %d oci %d sport %d dport %d dbucket %d samples %lf\n", start, end, len, oci, flow.sport, flow.dport, d_bucket, stats[hist][n][sym][d_bucket]);
		  if (shouldFilter(d_bucket, flow, c))
		    {
		      is_filtered = true;
		      c->wfilter_p[d_bucket] += len;
		      c->wfilter_s[d_bucket] += oci;
		      checkReady(d_bucket,c);
		    }
		}
	    }
	}
    }

  //  if (is_filtered)
  //{
  //  return;
  //}

  vector<int> d_buckets, s_buckets;
  
  for (int way = LHOST; way <= LPRST; way++) 
    {
      // Find buckets on which to work
      if (way == LHOST || way == LPREF || way == LHSYN || way == LPSYN || way == LHSYNACK || way == LPSYNACK || way == LHACK || way == LPACK || way == LHRST || way == LPRST)
	{
	  if (flow.dlocal)
	    {
	      // traffic to LHOST/LPREF
	      d_bucket = myhash(flow.dst, 0, way);
	      if (way == LHSYN  || way == LPSYN)
		if (flow.flags != SYN || flow.proto != TCP)
		  continue;
	      if (way == LHSYNACK  || way == LPSYNACK)
		if (flow.flags != SYNACK || flow.proto != TCP)
		  continue;
	      if (way == LHACK  || way == LPACK)
		if (flow.flags != ACK || flow.proto != TCP)
		  continue;
	      if (way == LHRST  || way == LPRST)
		if (flow.flags != RST || flow.proto != TCP)
		  continue;
	      c->databrick_p[d_bucket] += len;
	      c->databrick_s[d_bucket] += oci;
	      addSample(d_bucket, &fp, way);
	      instant_detect(c, curtime, d_bucket);
	    }
	  if (flow.slocal)
	    {
	      // traffic from LHOST/LPREF
	      s_bucket = myhash(flow.src, 0, way);
	      if (way == LHSYN || way == LPSYN)
		if ((flow.flags != SYNACK && flow.flags != ACK && flow.flags != RST) || flow.proto != TCP)
		  continue;
	      if (way == LHSYNACK || way == LPSYNACK)
		if (flow.flags != SYN || flow.proto != TCP)
		  continue;
	      if (way == LHACK || way == LPACK)
		if ((flow.flags != PUSH && flow.flags != PUSHACK) || flow.proto != TCP)
		  continue;
	      if (way == LHRST || way == LPRST)
		if (flow.flags != SYN || flow.proto != TCP)
		  continue;
	      c->databrick_p[s_bucket] -= len;
	      c->databrick_s[s_bucket] -= oci;
	      instant_detect(c, curtime, s_bucket);
	    }	      
	}
      else if (way == FPORT)
	{
	  if (flow.dlocal && isservice(flow.sport))
	    {
	      // traffic from FPORT
	      s_bucket = myhash(0, flow.sport, way);
	      //if (flow.dst == 732944783 && flow.sport == 53)
	      //cout<<"FPORT "<<s_bucket<<endl;
	      c->databrick_p[s_bucket] += len;
	      c->databrick_s[s_bucket] += oci;
	      addSample(s_bucket, &fp, way);
	      instant_detect(c, curtime, s_bucket);
	    }
	  if (flow.slocal && isservice(flow.dport))
	    {
	      // traffic to FPORT
	      d_bucket = myhash(0, flow.dport, way);
	      c->databrick_p[d_bucket] -= len;
	      c->databrick_s[d_bucket] -= oci;
	      instant_detect(c, curtime, d_bucket);
	    }
	}
      else if (way == LPORT)
	{
	  if (flow.dlocal && isservice(flow.dport))
	    {
	      // traffic to LPORT
	      d_bucket = myhash(0, flow.dport, way);
	      //if (flow.dst == 732944783 && flow.dport == 53)
	      //cout<<"LPORT "<<d_bucket<<endl;
	      c->databrick_p[d_bucket] += len;
	      c->databrick_s[d_bucket] += oci;
	      addSample(d_bucket, &fp, way);
	      instant_detect(c, curtime, d_bucket);
	    }
	  if (flow.slocal && isservice(flow.sport))
	    {
	      // traffic from LPORT
	      s_bucket = myhash(0, flow.sport, way);
	      c->databrick_p[s_bucket] -= len;
	      c->databrick_s[s_bucket] -= oci;
	      instant_detect(c, curtime, s_bucket);
	    }
	}
      else if (way == LHFPORT || way == LPFPORT)
	{
	  if (flow.dlocal && isservice(flow.sport))
	    {
	      // traffic from FPORT
	      s_bucket = myhash(flow.dst, flow.sport, way);
	      //if (flow.dst == 732944783 && flow.sport == 53)
	      //cout<<"LHFPORT "<<s_bucket<<endl;

	      c->databrick_p[s_bucket] += len;
	      c->databrick_s[s_bucket] += oci;
	      addSample(s_bucket, &fp, way);
	      instant_detect(c, curtime, s_bucket);
	    }
	  if (flow.slocal && isservice(flow.dport))
	    {
	      // traffic to FPORT
	      d_bucket = myhash(flow.src, flow.dport, way);
	      //if (d_bucket == 13207)
	      //cout<<d_bucket<<" Now is "<< c->databrick_s[d_bucket]<<endl;
	      c->databrick_p[d_bucket] -= len;
	      c->databrick_s[d_bucket] -= oci;
	      instant_detect(c, curtime, d_bucket);
	    }
	}
      else if (way == LHLPORT || way == LPLPORT)
	{
	  if (flow.dlocal && isservice(flow.dport))
	    {
	      // traffic to LPORT
	      d_bucket = myhash(flow.dst, flow.dport, way);
	      //if (flow.dst == 732944783 && flow.dport == 53)
	      //cout<<"LHLPORT "<<d_bucket<<endl;
	      c->databrick_p[d_bucket] += len;
	      c->databrick_s[d_bucket] += oci;
	      addSample(d_bucket, &fp, way);
	      instant_detect(c, curtime, d_bucket);
	    }
	  if (flow.slocal && isservice(flow.sport))
	    {
	      // traffic from LPORT
	      s_bucket = myhash(flow.src, flow.sport, way);
	      c->databrick_p[s_bucket] -= len;
	      c->databrick_s[s_bucket] -= oci;
	      instant_detect(c, curtime, s_bucket);
	    }
	}
    }
}


// Update statistics
void update_stats(cell* c)
{
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      for (int j=vol; j<=sym; j++)
	{
	  int data;
	  if (j == vol)
	    data = c->databrick_p[i];
	  else
	    data = c->databrick_s[i];

	  // Only update if everything looks normal 
	  if (!is_abnormal[i])
	    {
	      // Update avg and ss incrementally
	      stats[cur][n][j][i] += 1;
	      if (stats[cur][n][j][i] == 1)
		{
		  stats[cur][avg][j][i] =  data;
		  stats[cur][ss][j][i] = 0;
		}
	      else
		{
		  int ao = stats[cur][avg][j][i];
		  stats[cur][avg][j][i] = stats[cur][avg][j][i] +
		    (data - stats[cur][avg][j][i])/stats[cur][n][j][i];
		  stats[cur][ss][j][i] = stats[cur][ss][j][i] +
		    (data-ao)*(data - stats[cur][avg][j][i]);
		}
	    }
	}      
    }
  trained = (lasttime - firsttime);

  if (trained >= parms["min_train"])
    {
      if (!training_done)
	{
	  cout<<"Training has completed\n";
	  training_done = true;
	}
      firsttime = curtime;
     
      for (int x = ss; x >= n; x--)
	for (int j = vol; j <= sym; j++)
	  for(int i = 0; i<BRICK_DIMENSION; i++)
	  {
	    // Check if we have enough samples.
	    // If the attack was long maybe we don't
	    if (stats[cur][n][j][i] <
		parms["min_train"]*MIN_SAMPLES)
	      continue;

	    if (stats[cur][x][j][i] == 0)
	      stats[hist][x][j][i] = 0.5*stats[hist][x][j][i] + 0.5*stats[cur][x][j][i];
	    else
	      stats[hist][x][j][i] = stats[cur][x][j][i];
	    stats[cur][x][j][i] = 0;
	  }
    }
}


// This function detects an attack
void detect_attack(cell* c, double ltime)
{
  // For each bin
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      // Pull average and stdev for volume and symmetry
      double avgv = stats[hist][avg][vol][i];
      double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
      double avgs = stats[hist][avg][sym][i];
      double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));
      int volume = c->databrick_p[i];
      int asym = c->databrick_s[i];

      // Update cusum
      for (int type = 0; type <= 1; type++)
	{
	  int data = volume;
	  double mean = avgv;
	  double std = stdv;
	  if (type == 1)
	    {
	      data = asym;
	      mean = avgs;
	      std = stds;
	    }
	  double tmp = cusum[type][i] + data - mean - 3*std;
	  if (tmp > 0)    
	    cusum[type][i] = tmp;
	  else
	    cusum[type][i] = 0;
	}
      
      if (verbose & 0) // Block it temporarily
	{
	  ofstream out;
	  char filename[200];
	  sprintf(filename, "%s/bin%d.txt", sparms["logs"].c_str(), i);
	  out.open(filename, std::ios_base::app);
	  out<<pthread_self()<<" "<<(long)ltime<<"  "<<avgv<<" "<<stdv<<" "<<volume<<" "<<avgs<<" "<<stds<<" "<<asym<<" "<<is_attack[i]<<" "<<is_abnormal[i]<<endl;
	  out.close();
	  if (lastlogtime == 0)
	    lastlogtime = ltime;
	  if (ltime - lastlogtime >= DAY)
	    {
	      //system("./mvlogs");
	      lastlogtime = curtime;
	    }
	}
      if (is_attack[i] == true)
	{
	  // Check if we have collected enough matches
	  if (signatures[i].nm == MM)
	    {
	      alert_ready(c, i);
	    }
	  else
	    {
	      double diff = ltime - detection_time[i];
	      if (diff >= ADELAY)
		{
		  is_attack[i] = false;
		  detection_time[i] = 0;
		  clearSamples(i);
		}
	    }
	}
      else if (!is_attack[i])
	{
	  // Training is completed and both volume and symmetry are normal
	  if (training_done && !abnormal(vol, i, c) && !abnormal(sym, i, c))
	    {
	      // Reduce abnormal score
	      if (is_abnormal[i] > 0)
		{
		  is_abnormal[i] --;
		}
	      if (is_abnormal[i] == 0)
		clearSamples(i);
	    }
	}
    }
}

	
// Read pcap packet format
void
amonProcessingPcap(u_char* p, struct pcap_pkthdr *h,  double time) // (pcap_pkthdr* hdr, u_char* p, double time)
{
  // Start and end time of a flow are just pkt time
  double start = time;
  double end = time;
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
      amonProcessing(flow, bytes, start, end, oci); 
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

  if (flow.dst == 2197625602)
    printf("%lf %lf: FF bytes %d (%d) pkts %d (%d) sport %d dport %d\n", start, end, bytes, pbytes, pkts, ppkts, flow.sport, flow.dport);
  /* Is this outstanding connection? For TCP, connections without 
     PUSH are outstanding. For UDP, connections that have a request
     but not a reply are outstanding. Because bidirectional flows
     may be broken into two unidirectional flows we have values of
     0, -1 and +1 for outstanding connection indicator or oci. For 
     TCP we use 0 (there is a PUSH) or 1 (no PUSH) and for UDP/ICMP we 
     use +1. */
  int oci, roci = 0;
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
	  //cout<<"TCP flow from "<<flow.src<<":"<<flow.sport<<"->"<<flow.dst<<":"<<flow.dport<<" bytes "<<bytes<<" pkts "<<pkts<<" dur "<<dur<<" oci "<<oci<<" roci "<<roci<<" ppkts "<<ppkts<<" pbytes "<<pbytes<<endl;
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
  amonProcessing(flow, bytes, start, end, oci);
  // Now account for reverse flow too, if needed
  if (rbytes > 0)
    {
      flow_t rflow;
      rflow.src = flow.dst;
      rflow.sport = flow.dport;
      rflow.dst = flow.src;
      rflow.dport = flow.sport;
      rflow.proto = flow.proto;
      rflow.slocal = flow.dlocal;
      rflow.dlocal = flow.slocal;
      
      amonProcessing(rflow, rbytes, start, end, roci);
      //cout<<"Start "<<start<<" end "<<end<<" dur "<<dur<<" rbytes "<<rbytes<<" roci "<<roci<<" line "<<saveline<<" flags "<<flags<<endl; // Jelena
    }
  
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

  // This is where sampling would be handled
  int minpkts, minbytes;
  
  // Hack for FRGP
  if (pkts % 100 == 0)
    {
      minpkts = 100;
      minbytes = bytes/(pkts/100);
    }
  else
    {
      minpkts = 4096;
      minbytes = bytes/(pkts/4096+1);
    }
  
  pkts = (int)(pkts/(dur+1))+1;
  bytes = (int)(bytes/(dur+1))+1;

  if (pkts < minpkts)
    {
      pkts = minpkts;
      bytes = minbytes;
    }
  // End of hack for FRGP
  
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

  amonProcessing(flow, bytes, start, end, oci); 
}



// Ever so often go through flows and process what is ready
void *reset_transmit (void* lt)
{
  double ltime = *((double*) lt);
  // Make sure to note that you're running
  pthread_mutex_lock (&rst_lock);
  resetrunning = true;
  pthread_mutex_unlock (&rst_lock);
  
  // Serialize access to cells
  pthread_mutex_lock (&cells_lock);
  //cout<<"RS locked - will work on "<<cfront<<" c is "<<(&cells[cfront])<<"\n";

  lasttime = curtime;
  // We will process this one now
  int current = cfront;

  // This one will be next for processing
  cfront = (cfront + 1)%QSIZE;
  if (cfront == crear)
    cempty = true;
  
  // Serialize access to cells
  pthread_mutex_unlock (&cells_lock);

  
  cell* c = &cells[current];
  //cout<<"RS unlocked front "<<cfront<<" rear "<<crear<<" current "<<current<<" address "<<c<<"\n";
  
  // Check if there is an attack that was waiting
  // a long time to be reported. Perhaps we had too specific
  // signature and we will never collect enough matches
  // Serialize access to stats

  if (training_done)
    detect_attack(c, ltime);
  update_stats(c);

  std::cout.precision(5);

  // Now note that you're done
  pthread_mutex_lock (&rst_lock);
  resetrunning = false;
  pthread_mutex_unlock (&rst_lock);
  
  // Detect attack here
  pthread_exit (NULL);
}

// Save historical data for later run
void save_history()
{  
  // Only save if training has completed
  if (training_done)
    {
      ofstream out;
      out.open("as.dump", std::ios_base::out);
      out<<numattack<<endl;
      for (int t=cur; t<=hist; t++)
	{
	  for (int i=0;i<BRICK_DIMENSION;i++)
	    {
	      for (int j=vol; j<=sym; j++)
		{
		  out<<t<<" "<<i<<" "<<j<<" ";
		  out<<stats[t][n][j][i]<<" "<<stats[t][avg][j][i]<<" "<<stats[t][ss][j][i]<<endl;
		}
	    }
	}
      out.close();
    }
}


// Load historical data
void load_history()
{
  ifstream in;
  in.open("as.dump", std::ios_base::in);
  if (in.is_open())
    {
      in>>numattack;
      for (int t=cur; t<=hist; t++)
        {
          for (int i=0;i<BRICK_DIMENSION;i++)
            {
              for (int j=vol; j<=sym; j++)
                {
                  in>>t>>i>>j;
                  in>>stats[t][n][j][i]>>stats[t][avg][j][i]>>stats[t][ss][j][i];
                }
            }
        }
      in.close();
      training_done = true;
      cout<<"Training data loaded"<<endl;
    }  
}

// Print help for the program
void
printHelp (void)
{
  printf ("amon-senss\n(C) 2018 University of Southern California.\n\n");

  printf ("-h                             Print this help\n");
  printf ("-S                             Streaming input from stdin\n");
  printf ("-r <file|folder|iface>         Input is in given file or folder, or live on the specified iface\n");
  printf ("-l                             Load historical data from as.dump\n");
  printf ("-F <pcap|plive|ft|nf|fr>       Input is in this format\n");
  printf ("\t pcap - libpcap format in a file\n");
  printf ("\t plive - libpcap live read from interface\n");
  printf ("\t ft - flowtools format in a file\n");
  printf ("\t nf - netflow format in a file\n");
  printf ("\t fr - Flowride format in a file\n");
  printf ("-s <file>                      Start from this given file in the input folder\n");
  printf ("-e <file>                      End with this given file in the input folder\n");
  printf ("-f                             Simulate filtering, without this we don't print alerts\n");
  printf ("-v                             Verbose\n");
}


/*
// File or stream processing function
void processLine(std::function<void(char*, double)> func, int num_pkts, char* line, double epoch, double& start)
{  
  //cout<<"Processing "<<line<<endl; // Jelena
  // For now, if this is IPv6 flow ignore it
  if (strstr(line, ":") != 0)
    return;
  num_pkts++;
  if (firsttimeinfile == 0)
    firsttimeinfile = epoch;
  allflows++;
  processedflows++;
  if (allflows == INT_MAX)
    allflows = 0;
  if (allflows % 1000000 == 0)
    {
      double diff = time(0) - start;
      cout<<"Processed "<<allflows<<", 1M in "<<diff<<" curtime "<<curtime<<" last "<<lasttime<<" epoch "<<epoch<<endl;
      start = time(0);
    }
  // Each second
  int diff = curtime - lasttime;
  if (curtime - lasttime >= 1) 
    {
      pthread_mutex_lock (&cells_lock);
      cout<<std::fixed<<"Done "<<time(0)<<" curtime "<<curtime<<" lasttime "<<lasttime<<" flows "<<processedflows<<" lastbintime "<<lastbintime<<endl;
      // This one we will work on next
      crear = (crear + 1)%QSIZE;
      if (crear == cfront && !cempty)
	{
	  perror("QSIZE is too small\n");
	  exit(1);
	}
      // zero out stats
      cell* c = &cells[crear];
      //cout<<"Zeroing cell "<<crear<<" address "<<c<<endl;
      memset(c->databrick_p, 0, BRICK_DIMENSION*sizeof(long int));
      memset(c->databrick_s, 0, BRICK_DIMENSION*sizeof(long int));
      memset(c->wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
      memset(c->wfilter_s, 0, BRICK_DIMENSION*sizeof(int));	  
      // and it will soon be full
      cempty = false;
      pthread_mutex_unlock (&cells_lock);

      // If the previous reset didn't finish, cannot create new one
      while (true)
	{
	  pthread_mutex_lock (&rst_lock);
	  int rst = resetrunning;
	  pthread_mutex_unlock (&rst_lock);
	  if (!rst)
	    break;
	  usleep(1);
	}
      
      pthread_t thread_id;
      pthread_create (&thread_id, NULL, reset_transmit, NULL);
      pthread_detach(thread_id);
      processedflows = 0;
      lasttime = curtime;
    }
  func(line, start);
}
*/

// Define the function to be called when ctrl-c (SIGINT) is sent to process
void signal_callback_handler(int signum) {
   cout << "Caught signal " << signum << endl;
   // Terminate program
   save_history();
   exit(signum);
}

// Read one line from file according to format
double read_one_line(void* nf, char* format, char* line, u_char* p,  struct pcap_pkthdr *h)
{
  if (!strcmp(format, "nf") || !strcmp(format, "ft") || !strcmp(format,"fr"))
    {
      char* s = fgets(line, MAXLINE, (FILE*) nf);
      if (s == NULL)
	return -1;

      char tmpline[MAXLINE];
      strcpy(tmpline, line);
      if (!strcmp(format, "nf") || !strcmp(format, "ft"))
	{
	  if (strstr(tmpline, "|") == NULL)
	    return 0;
	  int dl = parse(tmpline,'|', &delimiters);
	  double epoch = strtol(tmpline+delimiters[0],NULL,10);
	  int msec = atoi(tmpline+delimiters[1]);
	  epoch = epoch + msec/1000.0;
	  return epoch;
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
	firsttime = epoch;
      num_pkts++;
      if (firsttimeinfile == 0)
	firsttimeinfile = epoch;
      allflows++;
      if (allflows % 1000000 == 0)
	{
	  double diff = time(0) - start;
	  cout<<"Processed "<<allflows<<", 1M in "<<diff<<endl;
	  start = time(0);
	}
      processedflows++;
      // Each second
      if (curtime - lasttime >= 1) 
	{
	  pthread_mutex_lock (&cells_lock);
	  lastbintime = curtime;
	  //cout<<std::fixed<<"Doneo "<<time(0)<<" curtime "<<curtime<<" lasttime "<<lasttime<<" flows "<<processedflows<<endl;
	  
	  // This one we will work on next
	  crear = (crear + 1)%QSIZE;
	  if (crear == cfront && !cempty)
	    {
	      perror("QSIZE is too small\n");
	      exit(1);
	    }
	  // zero out stats
	  cell* c = &cells[crear];
	  memset(c->databrick_p, 0, BRICK_DIMENSION*sizeof(long int));
	  memset(c->databrick_s, 0, BRICK_DIMENSION*sizeof(long int));
	  memset(c->wfilter_p, 0, BRICK_DIMENSION*sizeof(unsigned int));
	  memset(c->wfilter_s, 0, BRICK_DIMENSION*sizeof(int));
	  // and it will soon be full
	  cempty = false;
	  pthread_mutex_unlock (&cells_lock);
	  
	  pthread_t thread_id;
	  pthread_create (&thread_id, NULL, reset_transmit, &lastbintime);
	  pthread_detach(thread_id);
	  processedflows = 0;
	  lasttime = curtime;
	}
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
  
  while ((c = getopt (argc, argv, "hvlr:s:e:F:fS")) != '?')
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
	case 'S':
	  stream_in = true;
	  break;
	case 'r':
	  file_in = strdup(optarg);
	  label = file_in;
	  break;
	case 'f':
	  sim_filter = true;
	  break;
	case 'l':
	  load_history();
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
  numservices = loadservices("services.txt");
  loadprefixes("localprefs.txt");
  memset(is_attack, 0, BRICK_DIMENSION*sizeof(int));
  memset(is_abnormal, 0, BRICK_DIMENSION*sizeof(int));
  // Parse configuration
  parse_config(parms, sparms);
  // Load service port numbers
  noorphan = (bool) parms["no_orphan"];

  signal(SIGINT, signal_callback_handler);

  /* Connect to DB
  try {
    driver = get_driver_instance();
    con = driver->connect("tcp://127.0.0.1:3306", "amon-senss", "St33llab@isi");
    con->setSchema("AMONSENSS");
   }
  catch (sql::SQLException &e) {
    cerr<<"Could not connect to the DB\n";
  }
  */

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
  else //if (file_in)
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
	if (endfile && strstr(file,endfile) != 0)
	  break;
      }
    }
  save_history();
  return 0;
}
