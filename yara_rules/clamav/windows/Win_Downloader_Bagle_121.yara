rule Win_Downloader_Bagle_121
{
strings:
	$a0 = { fd8a14188855ff9090900fb645fc885418ff0fb645fde98c000000558bec81c4adfeffff8bfc5590908b6d00909090906a0c8d451c50568bf25e5790e891feffff9090906090909090fcad508bc2580bc0743f57528bd55a508bc8518bcd59ad5190908bd7508bc1588d3c0351905652e819ffffff558bef5d59e846fdffff9090585f508bc75803f0909090ebbb9090909089751490 }

condition:
	$a0
}

        