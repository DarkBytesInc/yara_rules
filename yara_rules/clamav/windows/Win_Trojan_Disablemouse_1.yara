rule Win_Trojan_Disablemouse_1
{
strings:
	$a0 = { 226d6f757365223d2272756e646c6c3332206d6f7573652c64697361626c65223e3e633a5c742e726567 }

condition:
	$a0
}

        
