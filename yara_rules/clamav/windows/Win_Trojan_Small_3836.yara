rule Win_Trojan_Small_3836
{
strings:
	$a0 = { 927b9da1bb70423eb41fd68d1dbea27a693d795e7ee0674a9610d88acf3c56c9504d1ec150ca634ae3ad03c9aad65d4503890211551f0ac1ea6d51cf6946d9f097495dc1e26d4d22ba501d4ac0a1feb569b604ce561052cf37 }

condition:
	$a0
}

        
