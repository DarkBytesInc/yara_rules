rule Win_Trojan_Lineage_264
{
strings:
	$a0 = { 554e9064c5482581d774409ecacc544c554c258c92c1a002c677dd4ec5d7bb77cff9d12e82d1aabf2c0bf0de6bcaca935e22696702390fd2ac1e7708e5cadb024afcc7d46bfc89bce034467b5cbc1dd436015d574c035225ccce4c00 }

condition:
	$a0
}

        
