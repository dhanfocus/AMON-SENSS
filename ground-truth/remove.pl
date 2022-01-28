# Remove lines for certain IPs
# from the given file

$usage = "$0 file IP1 IP2..\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    if ($_ !~ /^Attack/)
    {
	next;
    }
    $found = 0;
    for ($i = 1; $i <= $#ARGV; $i++)
    {
	if ($_ =~ /$ARGV[$i]/)
	{
	    $found = 1;
	    last;
	}
    }
    if (!$found)
    {
	print $_;
    }
}
