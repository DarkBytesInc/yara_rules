rule Win_Trojan_Shiny_3
{
strings:
	$a0 = { 1e0633ff8edf813e0400f600742d8cc048832e1304018ed8832e030040832e1200408e0612000e1f8d76fdb97801f3 }

condition:
	$a0
}

        
