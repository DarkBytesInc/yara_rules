rule Win_Worm_Autorun_222
{
strings:
	$a0 = { 776572743d22[0-54]5c68746d6c5c736372697074735c72656d6f76655f706f7075702e76627322 }

condition:
	$a0
}

        
