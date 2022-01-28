# Read the stats file and get all attacks, then select a few times before the attack and
# during the attack.

if ($#ARGV < 0)
{
    print $usage;
    exit 0;
}
my $preamble = "";
$fh = new IO::File('preamble.txt');
while(<$fh>)
{
    $preamble .= $_;
}
close($fh);
%attacks = ();
$start = 0;
@log = ();
$trace = "";
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    @items = split /\s+/, $_;

    #Attack 0 start 1589246894 end 1589262420
    if ($_ =~ /Attack/)
    {
	$i = $items[1];
	$attacks{$i}{'start'} = $items[3];
	$attacks{$i}{'end'} = $items[5];
	$attacks{$i}{'trace'} = "";
    }
    else
    {
	push(@log, $_);
	if (scalar(@log) > 20)
	{
	    shift(@log);
	}
	if ($start == 1)
	{
	    $trace .= $_;
	}
	if ($_ =~ /A/ && $start == 0)
	{
	    $start = 1;
	    for $l (@log)
	    {
		$trace .= $l;
	    }
	    $trace .= $_;
	}
	if ($_ =~ /A/ && $start == 1)
	{
	    #1589178076 src 65.46.119.160 proto 6 pkts 744 bytes  311296
	    $time = $items[0];
	    for $i (keys %attacks)
	    {	    
		if ($time <= $attacks{$i}{'end'} && $time >= $attacks{$i}{'start'} + 5)
		{
		    $start = 2;
		    $attacks{$i}{'trace'} = $trace;
		    $trace = "";
		}
	    }
	}
	if (($_ =~ /src/ || $_ =~ /dst/) && $_ !~ /A/)
	{
	    $start = 0;
	}
    }
}
print $preamble;
for $i (sort {$a <=> $b} keys %attacks)
{
    print "<tr><td><input value='Anomaly $i (click to show/hide)' type=button onclick=\"showhide('attack$i')\"></input></td><td><div  style=\"display:none\" id=\"attack$i\"><pre>$attacks{$i}{'trace'}</pre></div></td></tr>";
}
