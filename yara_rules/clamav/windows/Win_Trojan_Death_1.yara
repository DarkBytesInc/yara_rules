rule Win_Trojan_Death_1
{
strings:
	$a0 = { 486c853938cf914d34ce206f37e926f0630e89a0c6cd3e559210c7f0f64620c1bc9514e9f92dc0059567b1a49cd2586984ddc55fc3511c0686239c090c4574ed }

condition:
	$a0
}

        
