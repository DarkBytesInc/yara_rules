rule Win_Downloader_997_1
{
strings:
	$a0 = { cc0ae98f74f225a3029008d43c01c5c2d479509ae4d46343f2d45d28c8b2e9e736763a6f7e10d0a7d08bc6c86193d02e2ee0576cac6bcbac0c2308aeb4e026e29401c116e17e0de848eda0b51cc4ca8294cb87b3a913c5e1ae2de958 }

condition:
	$a0
}

        
