all: label tag prtag finalize

label: label.cc utils.cc utils.h
	g++ -g -o label label.cc utils.cc -lpcap

tag: tag.cc utils.cc utils.h
	g++ -g -o tag tag.cc utils.cc

prtag: process_tags.cc utils.cc utils.h
	g++ -g -o process_tags process_tags.cc utils.cc

finalize: finalize.cc utils.cc utils.h
	g++ -g -o finalize finalize.cc utils.cc -lpcap
