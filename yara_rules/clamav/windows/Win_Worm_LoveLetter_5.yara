rule Win_Worm_LoveLetter_5
{
strings:
	$a0 = { 44454c54524545202f5920433a5c0d0a3a4f4b0d0a4543484f20404543484f204f4646203e3e20433a5c554e41562e42 }

condition:
	$a0
}

        
