rule Win_Trojan_RiotsUMsDos_1
{
strings:
	$a0 = { cd218cd82d11008ed8803e00015a754fa103012d40007247a30301832e1201508e0612010e1fb9d801bf0001578bf7f3a4061fb81c35cd21891ed3028c }

condition:
	$a0
}

        
