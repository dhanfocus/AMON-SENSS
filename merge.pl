# Merge alerts so that we have fewer to compare with peakflow
# Specify alerts.txt file on the command line

$THRESH = 600;
$DELAY = 300;

$usage="$0 alerts-file\n";

%alerts = ();

if ($#ARGV < 0)
{
    print $usage;
    exit(1);
}
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    @items = split /\s+/, $_;
    $id = $items[0];
    $time = $items[2];
    $bytes = $items[5];
    $pkts = $items[6];
    if ($_ =~ m/(.*)(dst ip )(\d+\.\d+\.\d+\.\d+)(.*)/)
    {
	$target = $3;
	$text = $4;
    }
    else
    {
	next;
    }
    if ($_ =~ m/(.*)(src ip )(\d+\.\d+\.\d+\.\d+)(.*)(dst ip )(\d+\.\d+\.\d+\.\d+)(.*)/)
    {
	next;
    }
    if ($_ =~ m/(.*)(proto tcp and flags 0)/)
    {
	next;
    }
    else
    {
	$alerts{$target}{$id}{'text'} = $_;
	$alerts{$target}{$id}{'time'} = $time;
	$type = 0;
	if ($_ =~ /proto udp/ && $_ =~ /src port 53/)
	{
	    $type = 1;
	}
	elsif ($_ =~ /proto icmp/)
	{
	    $type = 2;
	}
	elsif ($_ =~ /proto udp/ && $_ =~ /src port 0/)
	{
	    $type = 8;
	}
	elsif ($_ =~ /proto udp/ && $_ =~ /src port 389/)
	{
	    $type = 16;
	}
	elsif ($_ =~ /proto udp/ && $_ =~ /src port 123/)
	{
	    $type = 256;
	}
	elsif ($_ =~ /proto tcp/ && $_ =~ /flags 2/)
	{
	    $type = 1024;
	}
	elsif ($_ =~ /proto tcp/ && $_ =~ /flags 16/)
	{
	    $type = 512;
	}
	elsif ($_ =~ /proto tcp/ && $_ =~ /flags 18/)
	{
	    $type = 32;
	}
	elsif ($_ =~ /proto tcp/ && $_ =~ /flags 4/)
	{
	    $type = 64;
	}
	$alerts{$target}{$id}{'type'} = $type;
	$alerts{$target}{$id}{'bytes'} = $bytes;
	$alerts{$target}{$id}{'pkts'} = $pkts;
    }
}
for $target (keys %alerts)
{
    $ptime = 0;
    $p = "";
    $bytes = 0;
    $pkts = 0;
    $type = 0;
    $pid = 0;
    for $id (sort {$a <=> $b} keys %{$alerts{$target}})
    {
	$diff = $alerts{$target}{$id}{'time'} - $ptime;
	#print "target $target time $alerts{$target}{$id}{'time'} ptime $ptime p $p diff $diff\n";
	if ($ptime == 0 || ($alerts{$target}{$id}{'time'} - $ptime > $THRESH))
	{
	    if ($p != "")
	    {
		if ($type > 0)
		{
		    print "$pid $start $end $target $bytes $pkts $type\n";
		}
	    }
	    $type = $alerts{$target}{$id}{'type'};
	    $start = $alerts{$target}{$id}{'time'};
	    $bytes = $alerts{$target}{$id}{'bytes'};
	    $pkts = $alerts{$target}{$id}{'pkts'};
	    $p = $alerts{$target}{$id}{'text'};
	    $pid = $id;
	}
	else
	{
	    $type |= $alerts{$target}{$id}{'type'};
	}
	$end = $alerts{$target}{$id}{'time'} + $DELAY;
	$ptime = $alerts{$target}{$id}{'time'};
	if ($bytes < abs($alerts{$target}{$id}{'bytes'}))
	{
	    $bytes = abs($alerts{$target}{$id}{'bytes'});
	}
	if ($pkts <  abs($alerts{$target}{$id}{'pkts'}))
	{
	    $pkts = abs($alerts{$target}{$id}{'pkts'});
	}
    }
    if ($type > 0)
    {
	print "$pid $start $end $target $bytes $pkts $type\n";
    }
}
