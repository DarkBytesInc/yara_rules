rule Win_Downloader_VB_211
{
strings:
	$a0 = { 410000041940001019400000000400d43240000000000000000000a1dc3240000bc07402ffe06824194000b880114000ffd0ffe0000000446f776e6c6f616446696c650000000050555841000000000000000045584543555441000c00400000000000000000004200000068 }

condition:
	$a0
}

        