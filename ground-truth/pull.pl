#  Specify the IP and the type to pull

$usage = "$0 IP type\n";
if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
$ip = $ARGV[0];
$type = int($ARGV[1]);
$fh = new IO::File("output.txt");
while (<$fh>)
{
    if ($_ !~ /^$ip /)
    {
	next;
    }
    @items = split /[\s\,]/, $_;
    $time = $items[1];

    for($i=2; $i<=$#items-3; $i+=4)
    {
	$itype = $items[$i];
	if ($itype == $type)
	{
	    print "$time $items[$i+1] $items[$i+2] $items[$i+3]\n";
	}
    }
}
