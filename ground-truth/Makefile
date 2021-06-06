all: label tag prtag newtag nprtag stag

label: label.cc utils.cc utils.h
	g++ -g -o label label.cc utils.cc -lpcap

tag: tag.cc utils.cc utils.h
	g++ -g -o tag tag.cc utils.cc

prtag: process_tags.cc utils.cc utils.h
	g++ -g -o prtag process_tags.cc utils.cc
