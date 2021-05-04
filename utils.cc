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

#include "utils.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sstream>
#include <iostream>
#include <fstream>

// We need this so sort would work
namespace patch
{
  template < typename T > std::string to_string( const T& n )
  {
    std::ostringstream stm ;
    stm << n ;
    return stm.str() ;
  }
}

// Convert string to address
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


// Convert address to IP string
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

// Print out signature/flow
string printsignature(flow_t s)
{
  string out;
  if (s.src != 0)
    out += ("src ip "+ toip(s.src));
  if (s.sport != -1 && (s.sport != -2 || s.proto != ICMP))
    {
      if (out.size() > 0)
	out += " and ";
      out += ("src port " + patch::to_string((unsigned short) s.sport));
    }
  if (out.size() > 0)
    out += " and ";
  out += ("dst ip " + toip(s.dst));
  if (s.dport != -1 && ((s.dport != -2 || s.proto != ICMP)))
    {
      if (out.size() > 0)
	out += " and ";
      out += ("dst port " + patch::to_string((unsigned short) s.dport));
    }
  if (s.proto == TCP || s.proto == UDP || s.proto == ICMP)
    {
      if (out.size() > 0)
	out += " and ";
      if (s.proto == TCP)
	out += "proto tcp";
      else if (s.proto == UDP)
	out += "proto udp";
      else if (s.proto == ICMP)
	out += "proto icmp";
    }
  if (s.proto == TCP)
    {
      out += (" and flags " + patch::to_string(s.flags));
    }
  return out;
}

// Sign of a number
int sgn(double x)
{
  if (x<0)
    return -1;
  else if (x>0)
    return 1;
  else
    return 0;
}

// Is the signature all zeros (i.e. the default signature)
int zeros(flow_t a)
{
  return (a.src == 0) + (a.sport == -1) + (a.dst == 0) + (a.dport == -1) + (a.proto == -1) + (a.flags == 0);
}

// Check if the signature contains all zeros
// proto doesn't count
bool empty(flow_t sig)
{
  return ((sig.src == 0) && (sig.sport == -1 || sig.sport == 0) &&
	  (sig.dst == 0) && (sig.dport == -1 || sig.dport == 0) && (sig.flags == 0));
}


// A signature is better if it has more items defined
// but we also want to make sure it isn't too specific
bool bettersig(flow_t a, flow_t b)
{
  if (empty(b))
    return 1;
   if ((zeros(a) <= zeros(b)) &&
       (a.src == 0 && ((a.sport != -1 && a.dport == -1) || (a.dport != -1 && a.sport == -1))))
    return 1;
  return 0;
}


extern map<unsigned int, struct shuffle_cell> memshuffle;
extern int BRICK_FINAL;
extern int shuffle_index;

// Simple hash function
// Take the second and third bytes, convert into int and mod
// Use service port instead of the last byte
int myhash(u_int32_t ip, unsigned short port, int way)
{
  // 1 - local ip, 2 - local pref /24, 3 - foreign port, 4 - local port,
  // 5 - localip+forport, 6 - localip+localport, 7 - localpref+forport, 8 - localpref+localport
  // 9 - localip+syn, 10 - localpref+syn, 11 - localip+synack, 12 - localpref+synack, 13 - localip+rst, 14 - localpref+rst
  if (memshuffle.find(ip) != memshuffle.end())
    {
      return memshuffle[ip].index + (int)way*(shuffle_index+BRICK_UNIT);
    }
  else
    {
      switch (way)
	{
	case LHOST:
	  return ip % BRICK_UNIT + shuffle_index;
	case LPREF:
	  return ((ip & 0xffffff00) % BRICK_UNIT) + BRICK_UNIT + 2*shuffle_index;
	case FPORT:
	  return (port % BRICK_UNIT) + 2*BRICK_UNIT + 3*shuffle_index;
	case LPORT:
	  return (port % BRICK_UNIT) + 3*BRICK_UNIT + 4*shuffle_index;
	case LHFPORT:
	  return ((ip + port) % BRICK_UNIT) + 4*BRICK_UNIT + 5*shuffle_index;
	case LHLPORT:
	  return ((ip + port) % BRICK_UNIT) + 5*BRICK_UNIT  + 6*shuffle_index;
	case LPFPORT:
	  return (((ip & 0xffffff00) + port) % BRICK_UNIT) + 6*BRICK_UNIT + 7*shuffle_index;
	case LPLPORT:
	  return (((ip & 0xffffff00) + port) % BRICK_UNIT) + 7*BRICK_UNIT + 8*shuffle_index;
	case LHSYN:
	  return (ip % BRICK_UNIT) + 8*BRICK_UNIT  + 9*shuffle_index;
	case LPSYN:
	  return ((ip & 0xffffff00) % BRICK_UNIT) + 9*BRICK_UNIT + 10*shuffle_index;
	case LHSYNACK:
	  return (ip % BRICK_UNIT) + 10*BRICK_UNIT + 11*shuffle_index;
	case LPSYNACK:
	  return ((ip & 0xffffff00) % BRICK_UNIT) + 11*BRICK_UNIT + 12*shuffle_index;
	case LHACK:
	  return (ip % BRICK_UNIT) + 12*BRICK_UNIT + 13*shuffle_index;
	case LPACK:
	  return ((ip & 0xffffff00) % BRICK_UNIT) + 13*BRICK_UNIT + 14*shuffle_index;
	case LHRST:
	  return (ip % BRICK_UNIT) + 14*BRICK_UNIT  + 15*shuffle_index;
	case LPRST:
	  return ((ip & 0xffffff00) % BRICK_UNIT) + 15*BRICK_UNIT + 16*shuffle_index;
	default:
	  return 0;
	}
    }
}

map<int,int> services;
int loadservices(const char* fname)
{
  ifstream inFile;
  int i = 1;
  inFile.open(fname);
  int port;
  while(inFile >> port)
    {
      services.insert(pair<int, int>(port, i++));
    }
  return services.size();
}

// Is this a service port?
bool isservice(int port)
{
  if (services.find(port) != services.end())
    return services[port];
  else
    return 0;
}


// Load local prefixes
set <u_int32_t> localprefs24;
set <u_int32_t> localprefs30;
void loadprefixes(const char* fname)
{
  ifstream inFile;
  int i = 0;
  inFile.open(fname);
  char ip[30];
  char pref[60];
  char mask[30];
  while(inFile >> pref)
    {
      cout<<"Prefix "<<pref<<endl;
      if (strstr(pref,":") > 0)
	{
	  cout<<"IPv6\n";
	  continue;
	}
      char* ptr = strstr(pref, "/");
      if (ptr == NULL)
	continue;
      *ptr=0;
      int mask = atoi(ptr+1);
      u_int32_t dpref = todec(pref);
      if (mask <= 24)
	{
	  // how many /24 are there?
	  int count = 1 << (24 - mask);
	  for (int i = 0; i < count; i++)
	    {
	      localprefs24.insert(dpref);
	      dpref += 256;
	    }
	}
      else
	{
	  // how many /30 are there"
	  int count = 1 << (30 - mask);
	  for (int i = 0; i < count; i++)
	    {
	      localprefs30.insert(dpref);
	      dpref += 4;
	    }
	}
    }
}

// Is this a local prefix?
bool islocal(u_int32_t ip)
{
  int pref1 = ip & 0xffffff00;
  int pref2 = ip & 0xfffffffc;
  if (localprefs24.find(pref1) != localprefs24.end())
    return true;
  if (localprefs30.find(pref2) != localprefs30.end())
    return true;
  return false;
}
