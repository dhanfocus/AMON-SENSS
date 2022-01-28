# Pull all traffic for a given target (to and from) from the given folder
# Specify .match file (to mine targets) and a folder where -final.gz files are

%targets = ();

$usage = "$0 .match folder\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    @items = split /\s+/, $_;
    $targets{$items[2]} = 1;
}
close($fh);
opendir(my $dh, $ARGV[1]);
@files = readdir($dh);
for $f (sort @files)
{
    print "$f\n";
    open(GU, "gunzip -c $ARGV[1]/$f|");
    while(<GU>)
    {
	for $t (keys %targets)
	{
	    if ($_ =~ /\t$t\t/)
	    {
		open(my $oh, ">>", "$t.total");
		print $oh $_;
		close($oh);
	    }
	}
    }
}
