rule Win_Trojan_Banbra_199
{
strings:
	$a0 = { 24d25cdd6da1775a4e1f15724bccfefd338a05622506d62a7b44aff18ee9ae7dfad972dbbc1cb9da3928c2ff9e8de6a4acdd32b13a7044b0e305370bf8a7765f61438e36a388ac24b5895fe9095767ee04c73603ad5e449be5b54d1f5fd2f19ebd5b518ff14064f6ccf0bc6cf10d4d3b63cdbb5afacb5214 }

condition:
	$a0
}

        
