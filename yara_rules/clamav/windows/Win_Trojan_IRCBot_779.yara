rule Win_Trojan_IRCBot_779
{
strings:
	$a0 = { e5766d97e493f5af69ebcc00304156454e534849ea4c484434c961e19672bb875b4728323015333c80454f6c1e1c207669 }

condition:
	$a0
}

        
