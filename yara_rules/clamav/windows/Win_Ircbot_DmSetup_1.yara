rule Win_Ircbot_DmSetup_1
{
strings:
	$a0 = { 59a8407555a80275420c018844068bfe81efa60d81c7460ea80c750af60501750556e87301 }

condition:
	$a0
}

        
