rule Win_Downloader_Small_3425
{
strings:
	$a0 = { 36c1aeb24500e7f6e03ae3b3cbf26cdc97db3accad34ba90b81c09fc1eafc481c9ccaa701d33e93af6ce3cefb173b734af929e8f5225c182edfd549dd2ba7f5868434bffc3664d2573229b6d0f900be4d5e6bb15a2702aa778eb25e43b161b1e4785af611e2ac2232918aed89fcab0 }

condition:
	$a0
}

        
