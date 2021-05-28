# Specify the file and column, tag values based on cusum

$THRESH = 5;
$MINS = 3600;
$MINV = 1;

$n = 0;
$mean = 0;
$ss = 0;
$std = 0;
$cusum = 0;
$max = 0;
$allowed = 0;

sub calc_cusum{
    $data = shift;
    if ($n > 1)
    {
	$tmp = $cusum + $data - $mean - 5*$std;
	if ($tmp > 0)
	{
	    $cusum = $tmp;
	    if ($cusum > 2*$THRESH)
	    {
		$cusum = 2*$THRESH;
	    }
	}
	else
	{
	    $cusum = 0;
	}
    }
}

sub update_means{
    $data = shift;
    
    # Check if abnormal
    if ($cusum <= $THRESH || $n < $MINS || $data <= $MINV*$max || $data <= $allowed)
    {
	if ($n == 1)
	{
	    $mean =  $data;
	    $ss = 0;
	    $std = 0;
	}
	else
	{
	    $ao = $mean;
	    $mean = $mean + ($data - $mean)/$n;
	    $ss = $ss + ($data - $ao)*($data - $mean);
	    $std = sqrt($ss/($n-1));
	}
	if ($data > $max)
	{
	    $max = $data;
	}
	print "$time $data $mean $std $cusum $max\n";
    }
    else
    {
	print "$time $data $mean $std $cusum $max A\n";
    }
}

$usage = "$0 file column start_time_in_epoch allowed\n";
if ($#ARGV < 3)
{
    print $usage;
    exit 0;
}
$file = $ARGV[0];
$column = int($ARGV[1]);
$fh = new IO::File($file);
$stime = $ARGV[2];
$allowed = $ARGV[3];
while (<$fh>)
{
    # Assumes data is sorted by time
    @items = split /\s/, $_;
    
    while($items[0] > $stime)
    {
	$time = $stime;
	$stime ++;
	$data = 0;
	$n++;
	calc_cusum($data);
	update_means($data);
    }

    $time = $items[0];
    $stime++;
    $data = $items[$column];
    $n++;

    calc_cusum($data);
    update_means($data);
}



