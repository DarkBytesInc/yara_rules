rule Win_Downloader_1010_1
{
strings:
	$a0 = { 6da249e5f22309db8382dc4cdbaeaf45bf350abd402fae7bb215e8b65a06b236cd17ce540876ddee68e052ab495ddb6533150eaba8e5c27eb8d9da689639d49200a6edba7201b7ad3b9d7e09be3754b66db33536efc2b72d37865dec }

condition:
	$a0
}

        
