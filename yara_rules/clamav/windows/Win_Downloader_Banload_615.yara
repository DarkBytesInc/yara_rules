rule Win_Downloader_Banload_615
{
strings:
	$a0 = { e99c2dfff4a939ffd29037ffb49473ffeeddccfffeefdffffff1e1fffff0e2fffff1e2fffff1e1fffff0e2ffffcbb8ffa37773ff0000008f0000002f000000000000000000000000e6d9a3fff8e593fbfff3a0ffeed180fff6eacbffd2b96cfff0cd4fffdda932ffc28a25ffce8f24ffe4a128ffe9a4 }

condition:
	$a0
}

        
