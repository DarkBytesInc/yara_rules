rule Win_Downloader_Banload_2066
{
strings:
	$a0 = { f83a4fad339966cf11b70c00aa0060d3b89c6d40005064ff35000000006489250000000033c089085045436f6d70616374320017353c68004812690187616c0c4603ff0460382c0ec730005800400d64e36103009747d9d6434ba387c87f0d1a7abf01a29900b038b73a0150726f6a656374c1001c16ed0857696e646f777320545ddc2e0061736b4d616e61 }

condition:
	$a0
}

        