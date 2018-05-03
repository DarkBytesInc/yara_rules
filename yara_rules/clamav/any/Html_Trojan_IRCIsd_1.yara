rule Html_Trojan_IRCIsd_1
{
strings:
	$a0 = { 7f6d495243913f104a5f66617a6572211b874a81716e3173206513a30f3370d52345acfdc76d61732be7 }

condition:
	$a0
}

        
