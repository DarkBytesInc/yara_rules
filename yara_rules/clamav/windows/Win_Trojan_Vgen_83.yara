rule Win_Trojan_Vgen_83
{
strings:
	$a0 = { 904e1702bb01018a27bb02018a0786c40503008bf08a8c0301e9e401e980002a2e434f4d002075bc921806000000 }

condition:
	$a0
}

        
