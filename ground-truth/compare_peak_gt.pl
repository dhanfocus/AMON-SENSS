# Read the first file (peakflow)
# and compare with ground truth

%gt = ();
%peak = ();

$usage = "$0 peakflow-alerts ground-truth-file\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
$fh = new IO::File($ARGV[1]);
$cp = 0;
while(<$fh>)
{
    $line = $_;
    #Attack on 15.73.218.139 from 1599758688 to 1599758827 dur 140 rate 117507 types 25
    @items = split /\s+/, $line;
    $ip = $items[2];
    $ip =~ s/\.\d+$/\.0/;
    $start = $items[4];
    $end = $items[6];
    $type = $items[12];
    $rate = $items[10]*8/1000000000;
    $gt{$ip}{$start}{'end'} = $end;
    $gt{$ip}{$start}{'type'} = $type;
    $gt{$ip}{$start}{'rate'} = $rate;
    $gt{$ip}{$start}{'text'} = $line;
    $gt{$ip}{$start}{'miss'} = 1;
}
close($fh);
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    #12323516 68.143.131.0 high 128150000 10700 20200818 12:05:0 - 13:20:0 16 1597777605 1597778095
    $line = $_;
    @items = split /\s+/, $line;
    $ip = $items[1];
    $start = $items[10];
    $end = $items[11];
    if ($end < 0)
    {
	$end = $start + 600;
    }
    $type = $items[9];
    $peak{$ip}{$start}{'end'} = $end;
    $peak{$ip}{$start}{'type'} = $type;
    $peak{$ip}{$start}{'text'} = $line;
    $peak{$ip}{$start}{'matched'} = 0;
    $cp++;
}
print("Peak attacks $cp\n");
close($fh);
$ga = 0;
$misss = 0;
$matched = 0;
$missed = 0;
$total = 0;
$delay = 0;
$m = 0;
for $ip (keys %gt)
{
    for $s (keys %{$gt{$ip}})
    {
	$ga++;
    }
    if (!exists($peak{$ip}))
    {
	$misss++;
	print "Missed $ip\n";
	for $s (keys %{$gt{$ip}})
	{
	    $missed++;
	    $dur = $gt{$ip}{$s}{'end'} - $s;
	    print "MissedA on $ip at $s rate $gt{$ip}{$s}{'rate'} dur $dur\n";
	    $total++;
	    $gt{$ip}{$s}{'miss'} = 1;
	}
    }
    else
    {
	for $s (keys %{$gt{$ip}})
	{
	    $total ++;
	    $found = 0;
	    for $ss (keys %{$peak{$ip}})
	    {
		$e = $gt{$ip}{$s}{'end'};
		$ee = $peak{$ip}{$ss}{'end'};
		if (($s <= $ss && $e >= $ss) || ($s <= $ee & $e >= $ee) ||
		    ($s >= $ss & $e <= $ee) || ($s <= $ss && $e >= $ee))
		{
		    $found = 1;
		    $d = $ss - $s;
		    if ($d < 0)
		    {
			$d = 0;
		    }
		    print("Adding delay $d ss $ss s $s\n");
		    $delay += ($d);
		    $m++;
		    print("Matched peak attack ip $ip start $ss end $peak{$ip}{$ss}{'end'} gt $s end $e\n");
		    $peak{$ip}{$ss}{'matched'} = 1;
		}
	    }
	    if ($found == 1)
	    {
		$dur = $gt{$ip}{$s}{'end'} - $s;
		print "Matched attack on $ip at $s rate $gt{$ip}{$s}{'rate'} dur $dur\n";
		$matched++;
		$gt{$ip}{$s}{'miss'} = 0;
	    }
	    else
	    {
		print "Missed attack on $ip at $s rate $gt{$ip}{$s}{'rate'}\n";
		$missed++;
		$gt{$ip}{$s}{'miss'} = 1;
	    }
	}
    }
}
$sa = 0;
$missg = 0;
for $ip (keys %peak)
{
    for $s (keys %{$peak{$ip}})
    {
	print "Attack on $ip start $s matched $peak{$ip}{$s}{'matched'}\n";
    }
}
$r = $delay/$m;
print "Detection delay $r\n";
@limits=(0, 0.1, 0.2, 0.5, 1, 100);
$l = 1;
while($l <= $#limits)
{
    $matched = 0;
    $missed = 0;
    for $ip (keys %gt)
    {
     	for $s (keys %{$gt{$ip}})
	{
            if ($gt{$ip}{$s}{'rate'} > $limits[$l-1] && $gt{$ip}{$s}{'rate'} <= $limits[$l])
            {
             	if ($gt{$ip}{$s}{'miss'} == 0)
		{
                    $matched++;
		}
                else
		{
                    $missed++;
		}
            }
	}
    }
    print "Rate $limits[$l] matched $matched missed $missed\n";
    $l++;
}
