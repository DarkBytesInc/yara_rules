rule Doc_Trojan_Replog_1
{
strings:
	$a0 = { 56436f6465203d2054442e436f64654d6f64756c652e4c696e657328312c2054442e436f64654d6f64756c652e436f756e744f664c696e657329 }
	$a1 = { 4f70656e2022493a5c5265702e6c6f672220466f7220417070656e64204173202331 }

condition:
	$a0 and $a1
}

        