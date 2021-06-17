# Remove attacks of type 128 or 4

$fh = new IO::File($ARGV[0]);
while(<$fh>)
{
    @items = split /\s+/, $_;
    if ($items[$#items] == 128 || $items[$#items] == 0 || $items[$#items] == 4)
    {
	next;
    }
    print $_;
}
