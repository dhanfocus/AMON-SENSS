#ifndef __UTILS_H
#define __UTILS_H

#include <openssl/sha.h>
#include <netinet/in.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <map>

using namespace std;

#define CONFIG_FILE "amon.config" // Configuration file
#define REPORT_THRESH 30          
#define MIN_FLOWS 100000          // This parameter and the next ensure we report on time intervals that
#define MIN_FRESH 10              // have seen most of their records
#define HMB 1.1                   // This is how much more a less specific signature should catch to be accepted
#define FILE_INTERVAL 3600        // Some files may have messed up records. We ignore records with times that are greater than first record's time plus 1h. If your files are bigger than 1h, adjust this interval accordingly.
#define BRICK_DIMENSION 256       // Number of bins
#define MAXLINE 255               // Maximum length for reading strings
#define AR_LEN 30                 // How many delimiters may be in an array
#define ATTACK_LOW 30             // A bin should be abnormal this many seconds to report attack 
#define ATTACK_HIGH 60            // A bin should be normal this many seconds to report end of attack
#define HIST_LEN 3600             // We replace old stats with new after this many seconds
#define MIN_TRAIN 3600            // We train for this many seconds before we start detecting
#define NUMSTD 5                  // How many STDEV around the mean are considered normal range
#define FILTER_THRESH 0.5         // A signature must describe at least this fraction of samples
#define SIG_FLOWS 100             // If we match this many flows to a signature, that is enough to evaluate it
#define SPEC_THRESH 0.05          // If symmetric flows matching this signature are this fraction of all flows that matched, this signature is not specific enough
#define MAX_DIFF 10               // How close should a timestamp be to the one where attack is detected

enum protos {TCP=6, UDP=17};       // Transport protocols we work with. We ignore other traffic

// 5-tuple for the flow
struct flow_t{
  unsigned int src;
  unsigned short sport;
  unsigned int dst;
  unsigned short dport;
  unsigned char proto;

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
  long start;
  long end;
  int len;
  int oci;
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
  map<int, flow_p> flows;
  map<flow_t,stat_r> signatures;
};

// Holds the samples for each bin
struct sample
{
  sample_p bins[BRICK_DIMENSION];
};

// Some function prototypes. Functions are defined in utils.cc
int hash(u_int32_t ip);
int sgn(double x);
int bettersig(flow_t a, flow_t b);
string printsignature(flow_t s);

#endif
