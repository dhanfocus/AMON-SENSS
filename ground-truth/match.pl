# Read attacks we detected and attacks from Peakflow
# and print matches

$usage="$0 our-attacks peakflow-attacks-new-format\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
%attacks=();
$fh = new IO::File($ARGV[0]);
$i = 0;
while(<$fh>)
{
    #Attack on 7.29.11.61 from 1589205408 to 1589205659 dur 58 rate 188416 types 4
    $line = $_;
    @items = split /\s+/, $_;
    $target = $items[2];
    $target =~ s/\.\d+$/\.0/;
    $start = $items[4];
    $stop = $items[6];
    $type = int($items[12]);
    if ($type == 4)
    {
	next;
    }
    $attacks{$i}{'target'} = $target;
    $attacks{$i}{'start'} = $start;
    $attacks{$i}{'stop'} = $stop;
    $line =~ s/\n//g;

    $attacks{$i}{'line'} = $line;
    $attacks{$i}{'type'} = $type;
    $attacks{$i}{'matched'} = 0;
    
    #print "Attack $i on $target start $start stop $stop\n";
    $i++;
}
close($fh);
$fh = new IO::File($ARGV[1]);
while(<$fh>)
{
    #11819559 2.36.86.0 low 7830000000 962720 20200207 16:45:0 - 17:55:0 4 1581122865 -1
    $line = $_;
    @items = split /\s+/, $line;
    $target = $items[1];
    $sev = $items[2];
    $start = $items[10];
    $stop = $items[11];
    $type = int($items[9]);
    if ($stop == -1)
    {
	$stop = $start + 300;
    }
    #print "Attack peakflow on target $target start $start stop $stop\n";
    $matched = 0;
    for $i (sort {$a <=> $b} keys %attacks)
    {
	if ($attacks{$i}{'target'} ne $target)
	{
	    next;
	}
	# Do we overlap, encompass or shortly precede this attack?
	if (($attacks{$i}{'start'} > $start && $attacks{$i}{'start'} < $stop) ||
	    ($attacks{$i}{'stop'} > $start && $attacks{$i}{'stop'} < $stop) ||
	    ($attacks{$i}{'start'} < $start && $attacks{$i}{'stop'} > $stop) ||
	    ($attacks{$i}{'stop'}  < $start && $attacks{$i}{'stop'} + 300 > $start)) # ||
	    #($attacks{$i}{'start'}  > $stop && $attacks{$i}{'start'} - 300 < $stop))
	{
	    $and = (($attacks{$i}{'type'} & $type));
	    #print "Potential match $attacks{$i}{'line'} matching type $attacks{$i}{'type'} and $type and is $and\n";
	    if ($and != 0)
	    {
		#print "$_ matches $attacks{$i}{'line'}\n";
		$attacks{$i}{'matched'} = "$sev $start $stop $type\n";
		$matched = 1;
	    }
	}
    }
    if ($matched == 0)
    {
	print "Didn't match $line\n";
    }
}
close($fh);

for $i (sort {$a <=> $b} keys %attacks)
{
    if ($attacks{$i}{'matched'})
    {
	$line = $attacks{$i}{'line'};
	$line =~ s/types \d+/types $attacks{$i}{'type'}/;
	$line =~ s/\n//;
	print "$attacks{$i}{'line'} $attacks{$i}{'matched'}";
    }
}
