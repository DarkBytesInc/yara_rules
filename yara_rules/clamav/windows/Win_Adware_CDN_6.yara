rule Win_Adware_CDN_6
{
strings:
	$a0 = { 536f6674776172655c434e4e49435c43646e436c69656e745c496e7374616c6c496e666f00 }

condition:
	$a0
}

        
