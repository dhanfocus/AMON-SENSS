# Specify file with matched attacks and folder with tagged files
# Extract specific target data and generate gnuplot showing
# which attack areas we tag. Also show what peakflow tags.

# Find max of col2 in between times start and stop defined by col1 
sub getmax
{
    my ($file, $col1, $col2, $start, $stop) = @_;
    print "Look into $file col $col1 for values in $col2 between $start and $stop\n";
    my $fh = new IO::File($file);
    my $max = 0;
    while(<$fh>)
    {
	@items = split /\s+/, $_;
	$time = int($items[$col1-1]);
	if ($time >= $start && $time <= $stop)
	{
	    $val = int($items[$col2-1]);
	    #print "Time $time val $val max $max\n";
	    if ($val > $max)
	    {
		$max = $val;
	    }
	}		
    }
    close($fh);
    return $max;
}

$usage="$0 attack.match.file folder.w.tags attack.peakflow.new.format\n";

if ($#ARGV < 2)
{
    print "$usage";
    exit 0;
}
%attacks = ();
%targets = ();
$fh = new IO::File($ARGV[0]);
$i = 0;
my %stats = ();
while(<$fh>)
{
    #Attack on 7.29.11.61 from 1589205408 to 1589205659 dur 58 rate 188416 types 4 high 1599791356 1599791670 24
    $line = $_;
    @items = split /\s+/, $_;
    $target = $items[2];
    $start = int($items[4]);
    $stop = int($items[6]);
    $rate = int($items[10]);
    $type = int($items[12]);
    $sev = $items[13];
    $pstart = $items[14];
    $pstop = $items[15];
    if ($pstop == -1)
    {
	$pstop = $pstart + 300;
    }
    
    $attacks{$i}{'target'} = $target;    
    $attacks{$i}{'start'} = $start;
    $attacks{$i}{'stop'} = $stop;
    $attacks{$i}{'rate'} = $rate;
    $attacks{$i}{'type'} = int($type);
    $attacks{$i}{'sev'} = $sev;
    $attacks{$i}{'pstart'} = $pstart;
    $attacks{$i}{'pstop'} = $pstop;
    print "Read type $type\n";
    $stats{$target}{$start} = $i;
    print "Pushed $i at target $target\n";
    
    $targets{$target} = 1;
    $target =~ s/\.\d+/\.0/;
    $attacks{$i}{'shorttarget'} = $target;

    $i++;    
}
close($fh);
my %map = ();
$fh = new IO::File("maptags.txt");
while(<$fh>)
{
    @items = split /\s+/, $_;
    $map{$items[1]}{'val'} = $items[2];
    $map{$items[1]}{'name'} = $items[0];
}
close($fh);
$fh = new IO::File($ARGV[2]);
$i = 0;
%peak=();
while(<$fh>)
{
    #11819559 2.36.86.0 low 7830000000 962720 20200207 16:45:0 - 17:55:0 4 1581122865 -1
    $line = $_;
    @items = split /\s+/, $line;
    $target = $items[1];
    $start = $items[10];
    $stop = $items[11];
    if ($stop == -1)
    {
	$stop = $start + 300;
    }
    $peak{$i}{'target'} = $target;
    $peak{$i}{'start'} = $start;
    $peak{$i}{'stop'} = $stop;
    $i++;
}
close($fh);
if (0)
{
    for $t (keys %targets)
    {
	print "Target $t\n";
	system("rm $t.txt");    
	opendir(my $dh, $ARGV[1]);
	@files = readdir($dh);
	for $f (sort @files)
	{
	    if ($f !~ /\.gz/)
	    {
		next;
	    }
	    system("gunzip -c $ARGV[1]/$f | grep $t >> $t.txt");
	}
    }
}
my $cnt = 1;
open(my $oh, ">", "plot.gnu");
open(my $ih, ">", "index.html");
print $oh "set terminal pngcairo\n";
print $oh "set xdata time\nset timefmt '%s'\nset format x '%H:%M'\n\n";
print $oh "set xlabel 'time (hour:min)'\nset ylabel 'pkts per sec'\n\n";
print $oh "set style rectangle back fc rgb \"yellow\" fs solid 1.0 border -1\n";
for $t (keys %targets)
{
    $at = 0;
    print "Target $t\n";
    for $tim (sort {$a <=> $b} keys %{$stats{$t}})
    {
	$i = $stats{$t}{$tim};
	print "Target $t attack $i from $attacks{$i}{'start'} to $attacks{$i}{'stop'}\n";
    }
    for ($j = 1 ; $j < $cnt; $j++)
    {
	print $oh "unset obj $j\n";
    }
    $cnt = 1;
    $rate = 0;

    for $s (keys %{$stats{$t}})
    {
	$i = $stats{$t}{$s};
	$r = $attacks{$i}{'rate'}/2;
	$max = getmax("$t.txt", 2, 6,$attacks{$i}{'start'}-1000, $attacks{$i}{'stop'}+1000);
	$max2 = $max/2;
	print $oh "set obj $cnt rect from " . $attacks{$i}{'start'} . ",0 to " . $attacks{$i}{'stop'} . ",graph 0.5\n";	
	$cnt++;
	print $oh "set obj $cnt rect from " . $attacks{$i}{'pstart'} . ",graph 0.5 to " . $attacks{$i}{'pstop'} . ",graph 1 fc \"green\"\n";
	$cnt++;
    }
    print $ih "<P>Target $t<p><img src=\"$t.png\" width=\"200\">\n";
    print $oh "set output '$t.png'\n";
    print $oh "set title 'Target $t all attacks, total'\n";
    print $oh "unset xrange\n";
    print $oh "set xdata time\nset timefmt '%s'\nset format x '%d/%H'\nset xlabel 'Time (day/hour)\n";
    print $oh "plot '$t.txt' u 2:6 pt 7 ps 1 notitle\n";
    
    for $s (sort {$a <=> $b} keys %{$stats{$t}})
    {
	$i = $stats{$t}{$s};
	print $ih "<br><img src=\"$t.$at.png\" width=\"200\">\n";
	my ($sec, $min, $hour, $day,$month,$year) = (gmtime($attacks{$i}{'start'}))[0,1,2,3,4,5];
	$year += 1900;
	$month += 1;
	print $oh "set output '$t.$at.png'\n";
	print $oh "set format x '%H:%M'\nset xlabel 'Time (hour:min)\n";
	print $oh "set title 'Target $t attack $at date $day/$month/$year total'\n";
	print $oh "set xrange [$attacks{$i}{'start'}-1000:$attacks{$i}{'stop'}+1000]\n";
	print $oh "plot '$t.txt' u 2:6 pt 7 notitle\n";
	for ($j = 524288; $j > 0; $j = $j/2)
	{
	    $and = $attacks{$i}{'type'} & $j;
	    if ($and > 0)
	    {
		if (0)
		{
		    print "perl pull.pl $t $map{$j}{'val'} $t.txt > $t.$j.txt type $attacks{$i}{'type'}\n";
		    system("perl pull.pl $t $map{$j}{'val'} $t.txt > $t.$j.txt");
		}
		#print $ih "<br>Attack $i on $t - component  $map{$j}{'name'}\n";
		print $ih "<img src=\"$t.$at.$j.png\" width=\"200\">\n";
		print $oh "set output '$t.$at.$j.png'\n";
		
		print $oh "set title 'Target $t attack $at component $map{$j}{'name'}'\n";
		print $oh "plot '$t.$j.txt' u 1:4 pt 7 notitle\n";
	    }
	}
	$at++;
    }
}

