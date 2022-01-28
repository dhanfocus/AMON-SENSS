# zip files in this dir if they are older than 5 min

opendir(my $dh, $ARGV[0]);
while(1)
{
    @files = readdir($dh);
    for $f (sort @files)
    {
	if ($f !~ /\.final$/)
	{
	    next;
	}
	$fh = new IO::File($ARGV[0] . "/" . $f);	
	my $epoch_timestamp = (stat($fh))[9];
	my $curtime = time();
	if ($curtime >= $epoch_timestamp + 300)
	{
	    print "Should zip $f\n";
	    system("gzip $ARGV[0]/$f");
	}
    }
    sleep(60);
}
