rule Win_Trojan_Hupigon_886
{
strings:
	$a0 = { 4b07b92dee7e9e98ffb1b0601fb5a6a1fde237c5db1238deae94c976dfb68ad560991b73f420be3b241813d5342bb210a5130f2eb80b0db300e295da8cf8cf737dbe9e3f80cba3a28f37af52d0e82c31bf7cda373761e60171e41848c5e134 }

condition:
	$a0
}

        
