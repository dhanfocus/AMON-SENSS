# Print nicely for hackathon how Peakflow alerts match our alerts
# Specify our file and Peakflow file

$usage="$0 our-matches peakflow-matches\n";

if ($#ARGV < 1)
{
    print $usage;
    exit 0;
}
$cnt = 0;
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
    $cnt++;    
}
close($fh);
$fh = new IO::File($ARGV[1]);
while(<$fh>)
{
    #12361842 15.73.218.0 medium 350750000 38740 20200910 10:25:0 - 11:40:0 25 1599758745 1599759129
    @items = split /\s+/, $_;
    $id = $items[0];
    $cattacks{$id}{'target'} = $items[1];
    $cattacks{$id}{'vol'} = $items[3];
    $cattacks{$id}{'pkt'} = $items[4];
    $cattacks{$id}{'start'} = $items[10];
    $cattacks{$id}{'stop'} = $items[11];
    $cattacks{$id}{'sev'} = $items[2];
    $cattacks{$id}{'type'} = $items[9];
}
close($fh);
for $id (sort {$a <=> $b} keys %cattacks)
{
    #print "<tr><td>C</td><td>$id</td><td>$cattacks{$id}{'start'}</td><td>$cattacks{$id}{'stop'}</td><td>$cattacks{$id}{'target'}</td><td>$cattacks{$id}{'type'}</td><td>$cattacks{$id}{'sev'}</td></tr>\n";
    print "<tr><td>C</td><td>$id</td><td>$cattacks{$id}{'start'}</td><td>$cattacks{$id}{'stop'}</td><td>$cattacks{$id}{'target'}</td><td>$cattacks{$id}{'type'}</td><td>$cattacks{$id}{'sev'}</td>\n";
    print "<td><table>\n";
    print "<tr><th>record type</th><th>ID</th><th>start_time</th><th>end_time</th><th>target</td><th>type</th><th>cID</th></tr>\n";
    for $cnt (sort {$myattacks{$a}{'start'} <=> $myattacks{$b}{'start'}} keys %myattacks)
    {
	if ($myattacks{$cnt}{'cstart'} == $cattacks{$id}{'start'})
	{
	    #print "<tr><td>I</td><td>$cnt</td><td>$myattacks{$cnt}{'start'}</td><td>$myattacks{$cnt}{'stop'}</td><td>$myattacks{$cnt}{'target'}</td><td>$myattacks{$cnt}{'type'}</td><td>$id</td><td><a href='graphn.html#$cnt'>Graph</a></tr>\n";
	    print "<tr><td>I</td><td>$cnt</td><td>$myattacks{$cnt}{'start'}</td><td>$myattacks{$cnt}{'stop'}</td><td>$myattacks{$cnt}{'target'}</td><td>$myattacks{$cnt}{'type'}</td><td>$id</td></tr>\n";
	}
    }
    print "</table></td></tr>\n";
}
