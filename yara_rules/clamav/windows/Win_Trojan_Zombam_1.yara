rule Win_Trojan_Zombam_1
{
strings:
	$a0 = { fb3308b66d2d12065bffffffef8b2af1cf0d0351a6c2f6460d40bcfa9fabda7998f7f7d8595e1b83a6dadbff8dff0a167954578fb66fb7336c80f9d53766a908e031bd36c0ff25fea92f907e2657502657a22de2842ebba39a97edffc2bffc24fd07d883cbffbb693395a38b5f }

condition:
	$a0
}

        
