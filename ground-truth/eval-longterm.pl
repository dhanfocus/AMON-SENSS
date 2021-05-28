# Specify trace file start and end and bpf to look for
# produce number of packets and bytes per second
# we only support "src/dst host" and "src/dst port" and proto

$|=1;
$usage = "$0 folder\n";
if ($#ARGV < 0)
{
    print $usage;
    exit 0;
}
$folder=$ARGV[0];
opendir(my $dh, $folder);
@files=readdir($dh);
for $f (sort @files)
{
    if(!-f $f){
	if ($f !~ /^\d+$/)
	{
	    next;
	}
	$cmd = "./label -r $folder/$f -F fr";
	print "$cmd\n";
	system($cmd);
	$cmd = "mv output.txt $f.stats.txt";
	print "$cmd\n";
	system($cmd);
	$cmd = "gzip $f.stats.txt";
	print "$cmd\n";
	system($cmd);
	$cmd = "./tag -r $f.stats.txt.gz > /dev/null";
	print "$cmd\n";
	system($cmd);
	$cmd = "mv tags.txt $f.tags.txt";
	print "$cmd\n";
	system($cmd);
	$cmd = "gzip $f.tags.txt";
	print "$cmd\n";
	system($cmd);
	$cmd="./prtag -r $f.tags.txt.gz > $f.attacks";
	print "$cmd\n";
	system($cmd);
    }
}
