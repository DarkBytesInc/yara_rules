rule Win_Downloader_Agent_35029
{
strings:
	$a0 = { 74d5800d8d948607e727cfa78f94d040ddf1fe2de3a7ad7ecef3de7cb529fd28e7f4ff79d443bc19e3a76d0ebaf9c276d4fbe92de3a3b073bcffe92de3a3b46fa0e3e92de3a3a86ba4e7e92de3a3ac67a8ebe92de3a3a063acefe92de3a3 }

condition:
	$a0
}

        
