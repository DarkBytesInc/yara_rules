rule Win_Downloader_Agent_35040
{
strings:
	$a0 = { 203b7247ff3da8b3f907a7f9b6d797b0df3eee88f326c9c36a40a842861aedca0acf94fec20beb6882fae9facabbbd998c074c71c2b7420ad71d51e58f86e22e443a4f628907e02d8b07acfdb2d7faded050a8dcff0a4e188052a8ce3f04 }

condition:
	$a0
}

        
