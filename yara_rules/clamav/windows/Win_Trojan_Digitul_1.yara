rule Win_Trojan_Digitul_1
{
strings:
	$a0 = { 4d61696e466f726d000d011c004469676974616c2055706c6f61642054726f6a616e204265746120 }

condition:
	$a0
}

        
