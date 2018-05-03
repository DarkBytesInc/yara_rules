rule Win_Proxy_Lager_36
{
strings:
	$a0 = { 6f447c244b4f0784b23064d4ff7562fb10c6e8829faa91948a3153a401c33261c3e763ecc7e16a62837f8611e57ab43acc2e4cd4fceb7fa6b71f1631219fa4a48b3a5c0dcf8d }

condition:
	$a0
}

        
