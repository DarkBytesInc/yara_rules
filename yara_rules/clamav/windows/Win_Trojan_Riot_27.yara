rule Win_Trojan_Riot_27
{
strings:
	$a0 = { 6572212121212199b440e8defee87600b90600e915004772656574696e677320746f2074 }

condition:
	$a0
}

        
