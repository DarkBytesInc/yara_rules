rule Win_Trojan_Lineage_189
{
strings:
	$a0 = { c9acecb787793b395df5e34aae39f84166706ffab7ac863fa9aa9396ad87c1e49dec1b6e70079190c76bb279cd9df0c40086a57016db2cada3666bd41ebfcf6ba518d40bbcbe9b33ae0a1dbda0a3761a14b49fe734233914580585e2a6dda11db0df05fdca8e3f87e1e6ddc1fa93fcec49370707bdfb8f0c74062bb2ddd7974f }

condition:
	$a0
}

        
