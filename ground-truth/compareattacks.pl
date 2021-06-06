# List all attack reports and compare to alerts

opendir(my $dh, ".");
@files = readdir($dh);
$missed = 0;
$matched = 0;
$extras = 0;
$extradur = 0;
for $f (sort @files)
{
    if ($f !~ /\d+\.stats\.txt\.gz\.nattacks/)
    {
	next;
    }
    @elems = split /\./, $f;
    $num = $elems[0];
    $fh = new IO::File($f);
    %cattacks={};
    %pattacks={};
    $ci = 0;
    $pi = 0;
    while (<$fh>)
    {
	#Attack on 128.138.51.16 from 1606361980 to 1606363180 dur 286 types 0 1 6 7
	@items = split /\s+/, $_;
	$dur = $items[8];
	$rdur = $items[6] - $items[4];
	$type = $items[10];
	if ($dur/$rdur < 0.1)
	{
	    #next;
	}
	if ($type == 4)
	{
	    next;
	}
	$cattacks{$ci}{'ip'} = $items[2];
	$cattacks{$ci}{'start'} = $items[4];
	$cattacks{$ci}{'stop'} = $items[6];
	$cattacks{$ci}{'match'} = 0;
	$ci++;
    }
    $fh = new IO::File("/archive/lterm/FlowRide/2020/$num/alerts.txt");
    <$fh>;
    while(<$fh>)
    {
	#12500778 138.86.163.65 high 377620000 39630 1605337236 1605338550 9
	@items = split /\s+/, $_;
	$pattacks{$pi}{'ip'} = $items[1];
	$pattacks{$pi}{'start'} = $items[5];
	$pattacks{$pi}{'stop'} = $items[6];
	$pattacks{$pi}{'sev'} = $items[2];
	$pi++;
    }
    print "========================\n$num\n";
    if ($ci == 0)
    {
	print "Invisible\n";
	for ($i = 0; $i<$pi; $i++)
	{
	    print "$num Attack $i on target $pattacks{$i}{'ip'} severity $pattacks{$i}{'sev'} missed\n";
	    $missed++;
	}
    }
    else
    {
	for ($i = 0; $i<$pi; $i++)
	{
	    print "$num Attack $i on target $pattacks{$i}{'ip'} severity $pattacks{$i}{'sev'} ";
	    $match = -1;
	    $mins = 10000;
	    $mine = 10000;

	    for ($j = 0; $j < $ci; $j++)
	    {
		if ($pattacks{$i}{'ip'} == $cattacks{$j}{'ip'})
		{
		    $cattacks{$j}{'match'} = 1;
		    $diffs = $pattacks{$i}{'start'} - $cattacks{$j}{'start'};
		    $diffe = $pattacks{$i}{'stop'} - $cattacks{$j}{'stop'};
		    if (($mins == 10000 || $diffs < $mins) && $diffs > 0)
		    {
			$match = $j;
			$mins = $diffs;
			$mine = $diffe;
		    }
		}		
	    }
	    
	    if ($match != -1)
	    {
		print " matched attack $match, peakflow starts late $mins peakflow ends late $mine\n";
		$matched++;
	    }
	    else
	    {
		print " missed\n";
		$missed++;
	    }
	}
	for ($j = 0; $j < $ci; $j++)
	{
	    if ($cattacks{$j}{'match'} == 0)
	    {
		$extras ++;
		$extradur += ($cattacks{$j}{'stop'} - $cattacks{$j}{'start'});
		$dur = ($cattacks{$j}{'stop'} - $cattacks{$j}{'start'});
		print "Extra $cattacks{$j}{'ip'} dur $dur\n";
	    }
	}
    }
}
print "Matched $matched missed $missed extras $extras dur $extradur\n";
