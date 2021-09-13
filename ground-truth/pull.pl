#  Specify the IP and the type to pull

$usage = "$0 IP type file\n";
if ($#ARGV < 2)
{
    print $usage;
    exit 0;
}
$ip = $ARGV[0];
$type = int($ARGV[1]);
$fh = new IO::File($ARGV[2]);
while (<$fh>)
{
    if ($_ !~ /^$ip /)
    {
	next;
    }
    @items = split /[\s\,]/, $_;
    $time = $items[1];

    for($i=2; $i<=$#items-7; $i+=7)
    {
	$itype = $items[$i];
	if ($itype == $type)
	{
	    print "$time $items[$i+1] $items[$i+2] $items[$i+3] $items[$i+4] $items[$i+5] $items[$i+6]\n";
	}
    }
}
