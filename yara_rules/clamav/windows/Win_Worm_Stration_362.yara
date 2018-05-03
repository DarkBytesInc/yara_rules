rule Win_Worm_Stration_362
{
strings:
	$a0 = { cf77ba804d19ea4fe7e2ccdf616cce57502db1abf18e0c6ad502d5a068cc7ac86d9c3e7a125857589ed8d832533413a8fbff51a4659d2f7b826b0a0308e11d028ed8fffbc1d3a75796079afed4677aa40c10781a993635b66faf7ef93e8376d19e9b64ff6d33e5a6ea777eaf46ab5dfa }

condition:
	$a0
}

        
