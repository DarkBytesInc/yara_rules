rule Win_Trojan_G_4
{
strings:
	$a0 = { 01b9d300810700004343e2f8e800005d81ed14018d966804b41acd21b4478db6940499cd211e06b82135cd21061f }

condition:
	$a0
}

        
