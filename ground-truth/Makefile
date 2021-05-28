all: label tag prtag newtag nprtag stag

label: label.cc utils.cc utils.h
	g++ -g -o label label.cc utils.cc -lpcap

tag: tag.cc utils.cc utils.h
	g++ -g -o tag tag.cc utils.cc

stag: stag.cc utils.cc utils.h
	g++ -g -o stag stag.cc utils.cc

newtag: newtag.cc utils.cc utils.h
	g++ -g -o newtag newtag.cc utils.cc

prtag: process_tags.cc utils.cc utils.h
	g++ -g -o prtag process_tags.cc utils.cc

nprtag: new_process_tags.cc utils.cc utils.h
	g++ -g -o nprtag new_process_tags.cc utils.cc
