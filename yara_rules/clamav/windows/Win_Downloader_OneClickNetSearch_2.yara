rule Win_Downloader_OneClickNetSearch_2
{
strings:
	$a0 = { 6965706c7567696e2e636f6d000049455000657865002573257300000000776200002573544d505f46494c455f25692e746d700000002f00000061746c2e646c6c004945506c7567696e536561726368302e646c6c007379737462302e646c6c }

condition:
	$a0
}

        