rule Win_Trojan__0313_0002_001_1
{
strings:
	$a0 = { 4233c933d2cd21b440b905008d96b300cd21b8024233c933d2cd21b440b972018d960500cd21 }

condition:
	$a0
}

        
