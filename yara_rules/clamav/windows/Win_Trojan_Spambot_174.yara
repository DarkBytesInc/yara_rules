rule Win_Trojan_Spambot_174
{
strings:
	$a0 = { ffffff26dbb77a31d4ca7cdfeb806dfc9b00be31761667687c842e5a75b3f27cd335798bffebff77188bf460fbf86d5ef2910f2ef64614fc89f4e3ffffffff7ff3439280fcc27aa4de480206173ac500ffbbcafcd7b7c581b3b1b9474c196eff1f7eff0364736b92701e4b4daf10 }

condition:
	$a0
}

        
