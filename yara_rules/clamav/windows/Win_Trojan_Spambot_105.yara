rule Win_Trojan_Spambot_105
{
strings:
	$a0 = { f57ff4dc2d65ffffffffb511269f6f92a937e903d6c4d15f583117f168d3b84c6bb09536821571ff0ffe474593e99f7d0313b4cbf3979394f8795c66ae9825ffffffff5539ca65cce66f2b7ace4dd704a6b6d21885feb620c27756e47dfe70aa488cdcebfffffff8f607606b943a }

condition:
	$a0
}

        
