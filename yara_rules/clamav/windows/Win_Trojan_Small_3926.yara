rule Win_Trojan_Small_3926
{
strings:
	$a0 = { 72ed49206eef112072e98d7176ce0dfb6fc8de3b5af15cfc6964cd4bab4c95195a6450c066efbde7bbe594fc6964cd655abb37fcc36837fcc363cc11fa740dfce45c52fbcf692c5ab7bf90877720dd3b5aba37fcc36437fcc3 }

condition:
	$a0
}

        
