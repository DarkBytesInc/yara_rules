rule Win_Trojan_Lineage_279
{
strings:
	$a0 = { 124a00f85ceaf84e52e613399d88f692acd708bc7c505bff6772b97955e77f47912bbc23fd4d0a90bd4dd1aa995ccd7851adf2b4b84dcb366f76023cb52cc99968a5e04148b4fe4b241f1df1f09f881617bd949dce673ce8fbd8e627 }

condition:
	$a0
}

        
