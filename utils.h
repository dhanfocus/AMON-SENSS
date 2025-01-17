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

#ifndef __UTILS_H
#define __UTILS_H

#include <netinet/in.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <streambuf>
#include <map>
#include <set>

using namespace std;

#define NUMB 5                     // How many different brick layers
#define ADELAY 35
#define NUMF 16                    // How many ways do we bin the traffic
enum ways{LHOST, LPREF, FPORT, LPORT, LHFPORT, LHLPORT, LPFPORT, LPLPORT, LHSYN, LPSYN, LHSYNACK, LPSYNACK, LHACK, LPACK, LHRST, LPRST};

#define BRICK_UNIT 3337            // How many bins we have. This should NOT be a power of 2
#define BRICK_DIMENSION NUMF*BRICK_UNIT // There are NUMF variants of how we can bin the traffic (e.g., by port, by dst IP, etc.)
#define SIGTIME 1
#define REPORT_THRESH 30
#define MIN_FRESH 10              // have seen most of their records
#define HMB 1.1                   // This is how much more a less specific signature should catch to be accepted
#define MAXLINE 1024              // Maximum length for reading strings
#define MM 10                     // Samples of flows that match a signature
#define AR_LEN 30                 // How many delimiters may be in an array
#define MAX_DIFF 10               // How close should a timestamp be to the one where attack is detected
#define NF 20                     // Number of different signatures for a flow
#define QSIZE 100                 // How many timestamps can I accumulate before processing

#define SIG_FLOWS 100             // This many flows must be collected, at least, to evaluate a signature
#define MIN_SAMPLES 0.1           // We must have samples for at least this fraction of training period to
                                  // roll over current stats into historical stats

#define ALPHA 0.5                 // Constant for weighted average of filtering effectiveness
#define EFF_THRESH 0.5            // If we're dropping less than this much traffic, we need a better signature
enum protos {TCP=6, UDP=17, ICMP=1}; // Transport protocols we work with. We ignore other traffic
enum flags {SYN=2, SYNACK=18, PUSH=8, PUSHACK = 24, RST=4, ACK=16}; // Flags we work with for detection of flag-specific attacks




class DataBuf : public streambuf
{
 public:
  DataBuf(char * d, size_t s) {
    setg(d, d, d + s);
  }
};

struct shuffle_cell
{
  int index;
  unsigned int len;
  unsigned int oci;
};

// 5-tuple for the flow
class flow_t{

 public:
  unsigned int src;
  short sport;
  unsigned int dst;
  short dport;
  unsigned char proto;
  int flags;
  int slocal;
  int dlocal;
  
  flow_t()
    {
      src = 0;
      sport = -1;
      dst = 0;
      dport = -1;
      proto = -1;
      flags = 0;
      slocal = 0;
      dlocal = 0;
    }
  
  bool operator<(const flow_t& rhs) const
  {
    if (src < rhs.src)
      {
	return true;
      }
    else if (src == rhs.src && sport < rhs.sport)
      {
	return true;
      }
    else if (src == rhs.src && sport == rhs.sport && dst < rhs.dst)
      {
	return true;
      }
    else if (src == rhs.src && sport == rhs.sport && dst == rhs.dst && dport < rhs.dport)
      {
	return true;
      }
    else if (src == rhs.src && sport == rhs.sport && dst == rhs.dst && dport == rhs.dport && proto < rhs.proto)
      {
	return true;
      }
    else if (src == rhs.src && sport == rhs.sport && dst == rhs.dst && dport == rhs.dport && proto == rhs.proto && flags < rhs.flags)
      {
	return true;
      }
    else
      return false;
  }
  
  bool operator==(const flow_t& rhs) const
  {
    // We don't compare flags since they have their separate bin
    return (src == rhs.src) && (dst == rhs.dst) && (sport == rhs.sport) && (dport == rhs.dport) && (proto == rhs.proto);
  }
};

// This wraps a flow and keeps some statistics
class flow_p
{
 public:
  long start;
  long end;
  int len;
  int oci;
  flow_t flow;

  flow_p()
    {
      start = 0;
      end = 0;
      len = 0;
      oci = 0;
    }

  flow_p(long start, long end, int len, int oci, flow_t flow)
    {
      this->start = start;
      this->end = end;
      this->len = len;
      this->oci = oci;
      this->flow = flow;
    }
};

// This holds all the flows for a given time interval. 
struct time_flow
{
  vector<flow_p> flows;
  int fresh;
};

// Some statistics for the flow
struct stat_r
{
  flow_t sig;
  int vol;
  int oci;
  int nm;
  char matches[MM][MAXLINE];
};

// A sample of flows that are used to derive a signature for the attack
struct sample_p
{
  flow_p flows[NF];
};

// Holds the samples for each bin
struct sample
{
  sample_p* bins;
  long timestamp;
};

// Function to sort by filename
struct sortbyFilename
{
  inline bool operator()(const string& a, const string& b ) const {
    int ai = a.find_last_of('/');
    int bi = b.find_last_of('/');
    return a.substr(ai+1) < b.substr(bi+1);
  }
};

// Some function prototypes. Functions are defined in utils.cc
int myhash(u_int32_t ip, unsigned short port, int way, int dim);
int sgn(double x);
bool bettersig(flow_t a, flow_t b);
string printsignature(flow_t s);
int loadservices(const char* fname);
void loadprefixes(const char* fname);
bool isservice(int port);
bool isspecial(int port);
bool islocal(u_int32_t ip);
int zeros(flow_t f);
unsigned int todec(string ip);
bool empty(flow_t sig);
string toip(unsigned int addr);
#endif
