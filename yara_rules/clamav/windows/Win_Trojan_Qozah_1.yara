rule Win_Trojan_Qozah_1
{
strings:
	$a0 = { e8000000008bf481063401000056ad2d5d1140008be88f85a4164000ffb5091840008f85f5174000e8d00c0000c3 }

condition:
	$a0
}

        
