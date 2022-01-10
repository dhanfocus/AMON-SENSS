# Read the first file (output of sum_alerts)
# and compare with ground truth

%gt = ();
%senss = ();

$usage = "$0 senss-sum-alerts ground-truth-file\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
$fh = new IO::File($ARGV[1]);
while(<$fh>)
{
    #Attack on 15.73.218.139 from 1599758688 to 1599758827 dur 140 rate 117507 types 25
    @items = split /\s+/, $_;
    $ip = $items[2];
    $start = $items[4];
    $end = $items[6];
    $type = $items[12];
    $rate = $items[10]*8/1000000000;
    $gt{$ip}{$start}{'end'} = $end;
    $gt{$ip}{$start}{'type'} = $type;
    $gt{$ip}{$start}{'rate'} = $rate;
}
close($fh);
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    #2.36.79.126 1600719240 1600719542 1.264665 11.736262768 1467032846 src port ...
    @items = split /\s+/, $_;
    $ip = $items[0];
    $start = $items[1];
    $end = $items[2];
    $senss{$ip}{$start}{'end'} = $end;
    $senss{$ip}{$ss}{'matched'} = 0;
}
close($fh);
$ga = 0;
$misss = 0;
$matched = 0;
$missed = 0;
$total = 0;
for $ip (keys %gt)
{
    for $s (keys %{$gt{$ip}})
    {
	$ga++;
    }
    if (!exists($senss{$ip}))
    {
	$misss++;
	print "Missed $ip\n";
	for $s (keys %{$gt{$ip}})
	{
	    $missed++;
	    print "Missed attack on $ip at $s rate $gt{$ip}{$s}{'rate'}\n";
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
	    for $ss (keys %{$senss{$ip}})
	    {
		$e = $gt{$ip}{$s}{'end'};
		$ee = $senss{$ip}{$ss}{'end'};
		if (($s <= $ss && $e >= $ss) || ($s <= $ee & $e => $ee) ||
		    ($s >= $ss & $e <= $ee) || ($s <= $ss && $e >= $ee))
		{
		    $found = 1;
		    $senss{$ip}{$ss}{'matched'} = 1;
		}
	    }
	    if ($found == 1)
	    {
		print "Matched attack on $ip at $s rate $gt{$ip}{$s}{'rate'}\n";
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
for $ip (keys %senss)
{
    for $s (keys %{$senss{$ip}})
    {
	$sa++;
    }
    if (!exists($gt{$ip}))
    {
	$missg++;
	print "Not exist $ip\n";
    }
}
print "Ground truth IPs " . scalar(keys %gt) . " attacks $ga matched $matched missed $missed total $total\n";
print "SENSS IPs " . scalar(keys %senss) . " attacks $sa\n";
print "SENSS detected $missg more, but missed $misss\n";
$fp = 0;
for $ip (keys %senss)
{
    for $ss (keys %{$senss{$ip}})
    {
	if ($senss{$ip}{$ss}{'matched'} == 0)
	{
	    $fp++;
	}
    }
}
print "SENSS false positives $fp\n";
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
