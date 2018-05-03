rule Unix_Trojan_MSShellcode_71
{
strings:
	$a0 = { 31db5389e66a40b70a53565389e186fb66ff016a6658cd80813e5136704e75f05ffcadffe6 }

condition:
	$a0
}

        
