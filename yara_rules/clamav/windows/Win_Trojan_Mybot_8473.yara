rule Win_Trojan_Mybot_8473
{
strings:
	$a0 = { c5fc7198e1166144aa734a28515ebdfb5cb49b10b5301bafe6d85c5787797f45100ea8a13bc9ea9b3d96c03597c55ef79458e99e2cc479f7ac85bfd7b6ef52a2cde4d6e3a2bb92e0dd970d9baa620a2e91d4408410 }

condition:
	$a0
}

        
