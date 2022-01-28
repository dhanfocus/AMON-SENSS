# Get rid of alerts that are too short

$usage="$0 file-w-alerts\n";

if ($#ARGV < 0)
{
    print $usage;
    exit 0;
}
$THRESH = 60;
my $fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    @items  = split /\s+/, $_;
    if ($_ !~ /Attack/)
    {
	next;
    }
    if (int($items[4]) > int($items[6]))
    {
	next;
    }
    print $_;
}
