rule Win_Trojan_Spambot_168
{
strings:
	$a0 = { abcea7edd4e45cb32cd916ff1fe0ff616cc70badff0e83bc97c78575df8f650963a08814e7edff6301ffa22dd180426297bcb39ccc0505b3fc33b5ffffffff857142d76b0bd9d02895e1b06041190ef14b1cae0b16814e16f23615b742eb0dffffffa3fb016e5504b58e7639029b }

condition:
	$a0
}

        
