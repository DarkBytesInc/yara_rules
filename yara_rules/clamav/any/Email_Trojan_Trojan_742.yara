rule Email_Trojan_Trojan_742
{
strings:
	$a0 = { 5375626a6563743a2068656c6c6f }
	$a1 = { 6f70656e2061747461636820646f63 }

condition:
	$a0 and $a1
}

        
