rule Win_Downloader_Agent_31818
{
strings:
	$a0 = { e7bdfc2363a098202056247b23e8ebecf350c323d86ac6af54a8eec06b6f24749fa26772218f183e3cc036781313cb64268f0c6e6d038c393ccd3e2366649196b7bbdecb7f6624b6a91ab1d5cb7bd1bca91ab1d1cf7fd5f4165470d3c28f }

condition:
	$a0
}

        
