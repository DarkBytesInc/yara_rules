rule Win_Downloader_1052_1
{
strings:
	$a0 = { 7880fab100b8da4db9c90080d9fb6c1517b82ed7120cb06db303c2ad10b505478c140ddb8efd14b8281a37ca4ad17915c38e01b53a1f7be9a812e0e707f60cb823ee4d18b8a2c29db6d5642e37588bc9b7e2eaee69dc6edb8364eacd }

condition:
	$a0
}

        
