rule Win_Trojan_VGEN_766
{
strings:
	$a0 = { 580511005053cb909090909090909080c3060656cb33db6089f7bef5008ed8b90800f3a406b8ff35f9cd21732cfab8 }

condition:
	$a0
}

        
