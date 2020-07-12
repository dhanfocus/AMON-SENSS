# Supply peakflowalerts.txt file and alerts.txt file
# try to match destinations and times and print out matches
# Also print statistics, what matched and what didn't
# specify peakflow alert file and alerts.txt

%palerts = ();
%aalerts = ();
%map = ();

$usage="$0 peakflowalerts.txt alerts.txt\n";

if ($#ARGV < 1)
{
    print $usage;
    exit(1);
}
$fh=new IO::File("/home/sunshine/newmap");
while(<$fh>)
{
    @items = split /\s+/, $_;
    $orig = $items[0];
    $anon = $items[1];
    $orig =~ s/\.\d+$/\.0/;
    $anon =~ s/\.\d+$/\.0/;
    $map{$orig} = $anon;
}
close($fh);
$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    @items = split /\s+/, $_;
    $id = $items[0];
    $items[1] =~  s/\.\d+$/\.0/;
    $palerts{$id}{'target'} = $map{$items[1]};
    $palerts{$id}{'severity'} = $items[2];
    $palerts{$id}{'rb'} = $items[3];
    $palerts{$id}{'rp'} = $items[4];
    $palerts{$id}{'start'} = $items[5];
    if ($items[6] == -1)
    {
        $items[6] = $items[5];
    }
    $palerts{$id}{'end'} = $items[6];
    $palerts{$id}{'atype'} = $items[7];
}
close($fh);
$fh = new IO::File($ARGV[1]);
while(<$fh>)
{
    #4 4 1589182786 START 3304 18597658 246032 src ip 18.198.139.135 and dst ip 0.0.0.0 and dst port 500 and proto udp
    @items = split /\s+/, $_;
    $id = $items[0];
    $aalerts{$id}{'start'} = $items[2];
    $aalerts{$id}{'rb'} = $items[5];
    $aalerts{$id}{'rp'} = $items[6];
    $aalerts{$id}{'text'} = $_;
}
for $p (sort {$a <=> $b} keys %palerts)
{
    $matched = 0;
    for $x (sort {$a <=> $b} keys %aalerts)
    {
	$t = $palerts{$p}{'target'};
	$t =~ s/\.0//;
	#print "Trying to match $t with $aalerts{$x}{'text'}";
	if ($aalerts{$x}{'text'} =~ / $t/)
	{
	    $diff1 = $aalerts{$x}{'start'} - $palerts{$p}{'start'};
	    if (abs($diff1) < 120)
	    {
		$pp = (abs($diff1) < 120);
		print "Matched alert $x with peakflow alert $p diff " . abs($diff1) . " comparison " . $pp . " between $aalerts{$x}{'start'} and $palerts{$p}{'start'} type $palerts{$p}{'atype'} and alert text $aalerts{$x}{'text'} \n";
		$matched = 1;
	    }
	}
    }
    if ($matched == 0)
    {
	print "Not matched alert $p target $t\n";
    }
}
