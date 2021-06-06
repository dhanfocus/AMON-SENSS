# Filter input stream so that we remove ports 80 and 443
while(<STDIN>)
{
    @items = split /\s+/, $_;
    $found = 0;
    for ($i = 6; $i <= 7; $i++)
    {
	if ($items[$i] == 80 || $items[$i] == 443)
	{
	    $found = 1;
	    last;
	}
    }
    if (!$found)
    {
	print $_;
    }
}
