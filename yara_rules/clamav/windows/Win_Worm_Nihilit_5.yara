rule Win_Worm_Nihilit_5
{
strings:
	$a0 = { 5c486964abb8656d652eabb8657865 }
	$a1 = { 5c616e67656c647573742e626174 }
	$a2 = { 633a5c5c616e67656c647573742e657865 }

condition:
	$a0 and $a1 and $a2
}

        
