rule Win_Trojan_VGEN_135
{
strings:
	$a0 = { a34d07e829010bc07526e80a01908cc00510002e010658072e0106500731c031db2e8e1650072e8b2652072eff }

condition:
	$a0
}

        
