rule Win_Trojan_SdBot_4446
{
strings:
	$a0 = { ec7ba2f685d35512e9ab08d075a136950e5c72f67930213009ea4f9acfee2953feaf037ed3745af8c782c743a8ff6eb8dea8fbe791ece43d2bd1fdfcce87aad08bb802c10a2821d9b1d378943260fd8e330b74ae6e4c251c2e077ea604580d4ad08b5c594bad01d1017c02ac }

condition:
	$a0
}

        
