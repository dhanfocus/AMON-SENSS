# Read a file for one target (given on cmdline) and print stats per proto
# such as number of sources, destinations, pkts, bytes, srcports and dstports

$usage="$0 attackfile.parsed attackfile.matched target.total\n";

our %stats=();
our %attacks=();
our $target = "";

sub printstats
{
    for $time (sort {$a <=> $b} keys %stats)
    {
	$type = "";
	for $i (keys %attacks)
	{
	    if ($time >= $attacks{$i}{'start'} && $time <= $attacks{$i}{'end'})
	    {
		if ($attacks{$i}{'matched'} ne "")
		{
		    $type = "A$i-CI-" . $attacks{$i}{'type'} . " C " . $attacks{$i}{'matched'};
		}
		else
		{
		    $type = "A$i-I-" . $attacks{$i}{'type'}  . " I " . "start $attacks{$i}{'start'} end $attacks{$i}{'end'}";
		}
	    }
	}
	print "\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
	for $t ('src', 'dst')
	{	
	    for $p (keys %{$stats{$time}{$t}})
	    {
		if ($p eq "6" || $p eq "1" || $p eq "17")
		{
		    print "$time $t $target proto $p pkts $stats{$time}{$t}{$p}{'pkts'} bytes  $stats{$time}{$t}{$p}{'bytes'} $type \n";
		    for $q (keys %{$stats{$time}{$t}})
		    {
			if ($q =~ /^$p ports/ || $q =~ /^$p flags/)
			{
			    if (exists($stats{$time}{$t}{$q}{'other'}))
			    {
				print "$time $t $target proto $q foreign IPs " . scalar(keys %{$stats{$time}{$t}{$q}{'other'}}) . " $type \n";
			    }
			    print "$time $t $target proto $q pkts $stats{$time}{$t}{$q}{'pkts'} bytes  $stats{$time}{$t}{$q}{'bytes'} $type \n";
			}
		    }
		    print "\n";
		}
		
	    }
	}
    }
    %stats=();
}


if ($#ARGV < 2)
{
    print $usage;
    exit 0;
}
$ARGV[2] =~ /(\d+\.\d+\.\d+\.\d+)(\.total)/;
$target = $1;
$fh = new IO::File($ARGV[0]);
$i = 0;
while(<$fh>)
{
    if ($_ !~ /Attack/)
    {
	next;
    }
    if ($_ !~ / $target /)
    {
	next;
    }
    @items = split /\s+/, $_;
    $start = $items[4];
    $end = $items[6];
    $type = $items[12];

    $attacks{$i}{'start'} = $start;
    $attacks{$i}{'end'} = $end;
    $attacks{$i}{'type'} = $type;
    $attacks{$i}{'matched'} = "";
    print "Attack $i start $attacks{$i}{'start'} end $attacks{$i}{'end'}\n";
    $i++;
}
close($fh);
$fh = new IO::File($ARGV[1]);
while(<$fh>)
{
    if ($_ !~ / $target /)
    {
	next;
    }
    #Attack on 2.50.4.65 from 1597811627 to 1597811782 dur 140 rate 160844 types 16394 high 1597811745 1597812113 16384
    @items = split /\s+/, $_;
    $start = $items[4];
    $end = $items[6];
    $cstart = $items[14];
    $cend = $items[15];
    for $i (keys %attacks)
    {
	if ($attacks{$i}{'start'} == $start && $attacks{$i}{'end'} == $end)
	{
	    $attacks{$i}{'matched'} = "start $cstart end $cend";
	}
    }
}
close($fh);
$fh = new IO::File($ARGV[2]);
$lasttime = 0;
while(<$fh>)
{
    @items = split /\s+/, $_;
    #1589176801	1589176801    65.46.119.160   22      77.17.61.97     58648   6       24      4210688         4096    B       o
    $stime = $items[0];
    $etime = $items[1];
    $dur = $etime - $stime;
    if ($dur < 1)
    {
	$dur = 1;
    }
    
    if ($lasttime == 0)
    {
	$lasttime = $etime;
    }
    $src = $items[2];
    $sport = $items[3];
    $dst = $items[4];
    $dport = $items[5];
    $proto = $items[6];
    $flags = $items[7];
    $bytes = int($items[8]/$dur);
    $pkts = int($items[9]/$dur);
    $type = $items[10];
    if ($sport > 1024 && $sport != 5353 && $sport != 1701 && $sport != 11211)
    {
	$sport = 'cli';
    }
    if ($dport > 1024 && $dport != 5353 && $dport != 1701 && $dport != 11211)
    {
	$dport = 'cli';
    }
    
    if ($src == $target)
    {
	$issrc = 'src';
	$forg = $dst;
    }
    else
    {
	$issrc = 'dst';
	$forg = $src;
    }
    #if ($etime - $lasttime >= 1)
    #{
#	printstats($lasttime);
#	$lasttime = $etime;
    #   }
    for ($time = $stime; $time <= $etime; $time++)
    {
	$stats{$time}{$issrc}{$proto}{'pkts'} += $pkts;
	$stats{$time}{$issrc}{$proto}{'bytes'} += $bytes;
	$stats{$time}{$issrc}{$proto . " flags " . $flags}{'pkts'} += $pkts;
	$stats{$time}{$issrc}{$proto . " flags " . $flags}{'bytes'} += $bytes;
	$stats{$time}{$issrc}{$proto . " ports " . $sport . "->" . $dport}{'pkts'} += $pkts;
	$stats{$time}{$issrc}{$proto . " ports " . $sport . "->" . $dport}{'bytes'} += $bytes;
	$stats{$time}{$issrc}{$proto . " ports " . $sport . "->" . $dport}{'other'}{$forg} = 1;
    }    
}
printstats();

