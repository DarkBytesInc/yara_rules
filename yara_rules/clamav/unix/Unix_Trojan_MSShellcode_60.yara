rule Unix_Trojan_MSShellcode_60
{
strings:
	$a0 = { 31db5389e66a40b70a53565389e186fb66ff016a6658cd80813e35766e4375f05ffcadffe6 }

condition:
	$a0
}

        
