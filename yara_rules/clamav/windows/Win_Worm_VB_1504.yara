rule Win_Worm_VB_1504
{
strings:
	$a0 = { 5c005700330032002e004d0073004e007a0079006d00e8002e006200610074 }

condition:
	$a0
}

        
