rule Win_Trojan_SdBot_2400
{
strings:
	$a0 = { d48d445acd6f168a2da5546ac8256d4552237aaaacd5cb79b688a2aada2ab115574b6aaaaf1af9f4f7e9efd3cfa79f4f3877de14f7813ce7fe79f3bef843ffeebbebff4dad20368000fe26f6aa00d2f187082e71df36b98384dff66ad7a77c2ac427da0136db9546705e46dc94928204 }

condition:
	$a0
}

        
