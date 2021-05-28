#include <fstream>
#include <iostream>

using namespace std;

int main(int argc, char** argv)
{
  ifstream in("alerts.txt", std::ifstream::ate | std::ifstream::binary);
  cout<<in.tellg();
}
