rule Doc_Trojan_SWSD_1
{
strings:
	$a0 = { 53656c656374696f6e2e547970655465787420546578743a3d222a20a7daac4fb367a659aabab76fb34ab0ada1a34a4f4b4552a1a4a14120abdc202a22 }

condition:
	$a0
}

        
