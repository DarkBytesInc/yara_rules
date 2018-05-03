rule Win_Worm_Ronoper_1
{
strings:
	$a0 = { f8b0c7556e69aa6c6c9e820840eaa33fb7930d42415c65846e6b923113c065794b474016f4ff214d6f72706865757320322e307bcd }

condition:
	$a0
}

        
