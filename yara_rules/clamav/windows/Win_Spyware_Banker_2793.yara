rule Win_Spyware_Banker_2793
{
strings:
	$a0 = { 5a071353b3a94bec595a1a1d0df5c2ed766a3437ef84b2ec9a4f1af00d77de964b425376a62fc2b4574209f5c2bd77c2d6d041d307a8465fc51aab17a2e0f0a6cc9ca9a8b116755fbd808f907addd77ee1f9684a00efb09bf1b29df579b67cf67fa200b49fecad98e4a59027dfa0 }

condition:
	$a0
}

        
