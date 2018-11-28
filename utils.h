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

#include <openssl/sha.h>
#include <netinet/in.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <streambuf>
#include <map>

using namespace std;

#define NUMF 5                    // How many ways do we bin the traffic
enum ways{FOR, LOC, LOCPREF, SERV, CLI};

#define BRICK_UNIT 701           // How many bins we have. This should NOT be a power of 2
#define BRICK_DIMENSION NUMF*BRICK_UNIT // There are NUMF variants of how we can bin the traffic (e.g., by port, by dst IP, etc.)
#define REPORT_THRESH 30
#define MIN_FLOWS 100000          // This parameter and the next ensure we report on time intervals that
#define MIN_FRESH 10              // have seen most of their records
#define HMB 1.1                   // This is how much more a less specific signature should catch to be accepted
#define MAXLINE 255               // Maximum length for reading strings
#define AR_LEN 30                 // How many delimiters may be in an array
#define MAX_DIFF 10               // How close should a timestamp be to the one where attack is detected
#define NF 8                      // Number of different signatures for a flow

#define FILTER_THRESH 0.5         // A signature must explain this much of asymmetry
#define SIG_FLOWS 100             // This many flows must be collected, at least, to evaluate a signature
#define MIN_SAMPLES 0.1           // We must have samples for at least this fraction of training period to
                                  // roll over current stats into historical stats

#define ALPHA 0.5                 // Constant for weighted average of filtering effectiveness
#define EFF_THRESH 0.5            // If we're dropping less than this much traffic, we need a better signature
enum protos {TCP=6, UDP=17};      // Transport protocols we work with. We ignore other traffic

class DataBuf : public streambuf
{
 public:
  DataBuf(char * d, size_t s) {
    setg(d, d, d + s);
  }
};

// 5-tuple for the flow
struct flow_t{
  unsigned int src = 0;
  unsigned short sport = 0;
  unsigned int dst = 0;
  unsigned short dport = 0;
  unsigned char proto = 0;
  int slocal = 0;
  int dlocal = 0;
  
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
    else
      return false;
  }
  
  bool operator==(const flow_t& rhs) const
  {
    return (src == rhs.src) && (dst == rhs.dst) && (sport == rhs.sport) && (dport == rhs.dport) && (proto == rhs.proto);
  }
};

// This wraps a flow and keeps some statistics
struct flow_p
{
  long start = 0;
  long end = 0;
  int len = 0;
  int oci = 0;
  flow_t flow;
};

// This holds all the flows for a given time interval. 
struct time_flow
{
  vector<flow_p> flows;
  int fresh;
};

// This structure keeps some statistics on a candidate signature
struct stat_f
{
  long timestamp;
  int vol;
  int oci;
  flow_t sig;
  map <flow_t,int> matchedflows;
  map <flow_t,int> reverseflows;
  int nflows;
};

// Some statistics for the flow
struct stat_r
{
  int vol;
  int oci;
};

// A sample of flows that are used to derive a signature for the attack
struct sample_p
{
  flow_p flows[NF];
  //map<flow_t,stat_r> signatures;
};

// Holds the samples for each bin
struct sample
{
  sample_p bins[BRICK_DIMENSION];
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
int myhash(u_int32_t ip, unsigned short port, int way);
int sgn(double x);
int bettersig(flow_t a, flow_t b);
string printsignature(flow_t s);
int loadservices(const char* fname);
int loadprefixes(const char* fname);
int isservice(int port);
int islocal(u_int32_t ip);

#endif
