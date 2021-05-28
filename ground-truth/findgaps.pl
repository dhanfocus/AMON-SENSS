# Measure gaps between anomalies for the same IP
# specify file with original alerts and the one with new alerts

$usage="$0 nattacks.txt alerts.txt\n";

if ($#ARGV < 1)
{
    print "$usage";
    exit 1;
}
$fh = new IO::File($ARGV[0]);
%cattacks=();
%pattacks=();
$ci = 0;
$pi = 0;
while (<$fh>)
{
    #48: Attack on 128.138.51.16 from 1606361980 to 1606363180 dur 286 types 0 1 6 7
    @items = split /\s+/, $_;
    $id = $items[0];
    $id =~ s/\://;
    $dur = $items[9];
    $rdur = $items[7] - $items[5];
    $type = $items[11];
    #print "Attack id $id dur $dur type $type\n";
    if ($type == 4)
    {
	next;
    }
    $cattacks{$id}{$ci}{'ip'} = $items[3];
    $cattacks{$id}{$ci}{'start'} = $items[5];
    $cattacks{$id}{$ci}{'stop'} = $items[7];
    $cattacks{$id}{$ci}{'match'} = 0;
    $ci++;
}
close($fh);
$fh = new IO::File($ARGV[1]);
<$fh>;
while(<$fh>)
{
    #12500778 138.86.163.65 high 377620000 39630 1605337236 1605338550 9
    @items = split /\s+/, $_;
    $pattacks{$pi}{'ip'} = $items[1];
    $pattacks{$pi}{'start'} = $items[5];
    $pattacks{$pi}{'stop'} = int($items[6]);
    if ($pattacks{$pi}{'stop'} == -1)
    {
	$pattacks{$pi}{'stop'} = $items[5]+300;
    }
    $pattacks{$pi}{'sev'} = $items[2];
    #print "Attack on $items[1] start  $pattacks{$pi}{'start'} stop  $pattacks{$pi}{'stop'} sev $items[2]\n";
    $pi++;
}

for $id (sort {$a <=> $b} keys %cattacks)
{
    $matched = 0;
    $matchednum = 0;
    $actualtime = 0;
    $missed = 0;
    $extras = 0;
    $extradur = 0;
    %actualtime = ();

    for ($i = 0; $i<$pi; $i++)
    {
	$mins = 10000;
	$mine = 10000;
	$match = -1;
	
	#print "Attack $i on target $pattacks{$i}{'ip'} severity $pattacks{$i}{'sev'} ";

	$actualtime{$pattacks{$i}{'ip'}} += $pattacks{$i}{'stop'} - $pattacks{$i}{'start'};

	for $j (keys %{$cattacks{$id}})
	{
	    if ($pattacks{$i}{'ip'} eq $cattacks{$id}{$j}{'ip'})
	    {
		$cattacks{$id}{$j}{'match'} = 1;
		$diffs = $pattacks{$i}{'start'} - $cattacks{$id}{$j}{'start'};
		$diffe = $pattacks{$i}{'stop'} - $cattacks{$id}{$j}{'stop'};
		#print "pattack stop  $pattacks{$i}{'stop'} cattack $cattacks{$id}{$j}{'stop'}\n";
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
	    #print " matched attack $j, peakflow starts late $mins peakflow ends late $mine\n";
	    $matched++;
	}
	else
	{
	    #print " missed\n";
	    $missed++;
	}
    }
    for $j (keys %{$cattacks{$id}})
    {
	#print "$id cattack $j target $cattacks{$id}{$j}{'ip'} type $cattacks{$id}{$j}{'type'} match $cattacks{$id}{$j}{'match'}\n";
	if ($cattacks{$id}{$j}{'match'} == 0)
	{
	    $extras ++;
	    $extradur += ($cattacks{$id}{$j}{'stop'} - $cattacks{$id}{$j}{'start'});
	    $dur = ($cattacks{$id}{$j}{'stop'} - $cattacks{$id}{$j}{'start'});
	    #print "Extra $cattacks{$j}{'ip'} dur $dur\n";
	}
	else
	{
	    
	    $matchednum++;

	}
    }    
    $results{$id}{'matched'} = $matched;
    $results{$id}{'matchednum'} = $matchednum;
    $results{$id}{'missed'} = $missed;
    $results{$id}{'extras'} = $extras;
}
for $id (sort {$a <=> $b} keys %cattacks)
{
    %ips=();
    for $i (sort {$a <=> $b} keys %{$cattacks{$id}})
    {
	$ip = $cattacks{$id}{$i}{'ip'};
	$prev = $cattacks{$id}{$i}{'stop'};
	for $j (sort {$a <=> $b} keys %{$cattacks{$id}})
	{
	    if ($j <= $i)
	    {
		next;
	    }
	    if ($cattacks{$id}{$j}{'ip'} != $ip)
	    {
		next;
	    }
	    if (exists($ips{$ip}))
	    {
		next;
	    }
	    $diff = $cattacks{$id}{$j}{'start'} - $prev;
	    $prev = $cattacks{$id}{$j}{'stop'};
	    print "$id $ip diff $diff\n";
	}
	$ips{$ip} = 1;
    }
}
