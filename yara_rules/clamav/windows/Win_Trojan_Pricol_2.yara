rule Win_Trojan_Pricol_2
{
strings:
	$a0 = { f716b828de1ccaabf8d2fb79cd71066defe8eb4a14edaa62c810c07ca88dfbfbd1abf22af80d2558f9a5d3501c9bfefc736299a19be691d8339baae88a6635cbce3ce748627d215bdd7a42b57ed53f120681c7f3d1b7ff4364ffa15a83c5d2ad9ff22b2949e3127c50a98979745e }

condition:
	$a0
}

        
