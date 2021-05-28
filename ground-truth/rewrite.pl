# Deal with negative numbers for ints that are bigger than MAX_INT

while(<STDIN>)
{
    @items = split /[\s\,]/, $_;
    $time = $items[1];
    $ip = $items[0];
    print "$ip $time ";
    for($i=2; $i<=$#items-3; $i+=4)
    {
	$itype = $items[$i];
	$src = $items[$i+1];
	$rate = $items[$i+2];
	$pkts = $items[$i+3];
	$tag = $items[$i+4];
	if ($rate < 0)
	{
	    $rate += 2147483647
	}
	print "$itype $src $rate $pkts $tag";
	if ($i+4< $#items-3)
	{
	    print ", ";
	}
    }
    print "\n";
}
