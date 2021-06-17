# Specify file with matched attacks and folder with tagged files
# Extract specific target data and generate gnuplot showing
# which attack areas we tag. Also show what peakflow tags.

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
while(<$fh>)
{
    #Attack on 7.29.11.61 from 1589205408 to 1589205659 dur 58 rate 188416 types 4
    $line = $_;
    @items = split /\s+/, $_;
    $target = $items[2];
    $start = $items[4];
    $stop = $items[6];
    $rate = int($items[10]);
    $type = int($items[12]);

    $attacks{$i}{'target'} = $target;
    
    $attacks{$i}{'start'} = $start;
    $attacks{$i}{'stop'} = $stop;
    $attacks{$i}{'rate'} = $rate;

    $targets{$target} = 1;
    $target =~ s/\.\d+/\.0/;
    $attacks{$i}{'shorttarget'} = $target;
    $i++;
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
print $oh "set terminal pdfcairo color enhanced\n";
print $oh "set xdata time\nset timefmt '%s'\n\n";
print $oh "set style rectangle back fc rgb \"yellow\" fs solid 1.0 border -1\n";
for $t (keys %targets)
{
    for ($j = 1 ; $j < $cnt; $j++)
    {
	print $oh "unset obj $j\n";
    }
    $cnt = 1;
    $rate = 0;
    for $i (keys %attacks)
    {
	if ($attacks{$i}{'target'} eq $t)
	{
	    print $oh "set obj $cnt rect from " . $attacks{$i}{'start'} . ",0 to " . $attacks{$i}{'stop'} . "," . $attacks{$i}{'rate'} . "\n";
	    if ($rate <  $attacks{$i}{'rate'})
	    {
		$rate =  $attacks{$i}{'rate'};
	    }
	    $cnt++;
	}
    }
    $shorttarget = $t;
    $shorttarget =~ s/\.\d+$/\.0/;
    $erate = 2*$rate;
    for $i (keys %peak)
    {
	print "Checking $shorttarget with $peak{$i}{'target'}\n";
	if ($peak{$i}{'target'} eq $shorttarget)
	{
	    print $oh "set obj $cnt rect from " . $peak{$i}{'start'} . ",$rate to " . $peak{$i}{'stop'} . ",$erate fc \"green\"\n";
            $cnt++;   
	}	
    }
    print $oh "set output '$t.pdf'\n";
    print $oh "set yrange [:$erate]\n";
    print $oh "plot '$t.txt' u 2:6 ps 0.2 pt 7\n";
}

