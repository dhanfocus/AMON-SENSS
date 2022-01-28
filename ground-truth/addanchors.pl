# Add anchors to existing graphs.html
# Specify matched alert file and graph file

$usage = "$0 matched-alerts graphs.html\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
my $cnt = 0;
%myattacks = ();
%cattacks = ();
my $fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    #Attack on 15.11.52.228 from 1600753655 to 1600753767 dur 113 rate 37160 types 24 high 1600752885 1600754060 25
    @items = split /\s+/, $_;
    $myattacks{$cnt}{'target'} = $items[2];
    $myattacks{$cnt}{'start'} = $items[4];
    $myattacks{$cnt}{'stop'} = $items[6];
    $myattacks{$cnt}{'type'} = $items[12];
    $myattacks{$cnt}{'sev'} = $items[13];
    $myattacks{$cnt}{'cstart'} = $items[14];
    $myattacks{$cnt}{'cstop'} = $items[15];
    $myattacks{$cnt}{'ctype'} = $items[16];
    $myattacks{$cnt}{'image'} = "";
    $cnt++;
}
close($fh);
$fh = new IO::File($ARGV[1]);
while(<$fh>)
{
    if ($_ =~ /(Target) (\d+\.\d+\.\d+\.\d+)/)
    {
	$target = $2;
    }
    elsif( $_ =~ /br/)
    {
	for $cnt (sort {$myattacks{$a}{'start'} <=> $myattacks{$b}{'start'}} keys %myattacks)
	{
	    if ($target eq  $myattacks{$cnt}{'target'} &&  $myattacks{$cnt}{'image'}  eq "")
	    {
		$myattacks{$cnt}{'image'} = "found attack $cnt\n";
		print "<a name='$cnt'>";
		last;
	    }
	}
    }
    print "$_";
}

