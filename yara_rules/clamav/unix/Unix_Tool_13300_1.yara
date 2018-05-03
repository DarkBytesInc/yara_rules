rule Unix_Tool_13300_1
{
strings:
	$a0 = { ffff0430ffff0530e60f0234cc484903ffff1004ab0f022455f046206606ff23c2f9ec236606bd239af9acaf9ef9a6af9af9bd23212080012128a003cccd4403 }

condition:
	$a0
}

        
