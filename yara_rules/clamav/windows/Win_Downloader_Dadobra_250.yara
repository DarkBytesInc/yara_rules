rule Win_Downloader_Dadobra_250
{
strings:
	$a0 = { 4cff19d255f4cd991fe34c6499675e7aacf21c66f0669e03f6e2a4f63a79a20b3e995e86c0fc9f6f0a8843292becb1851734b1c966fbba26bd79d4eeca8eef92223ea4c90bd9900421891a558b46627fede8372915 }

condition:
	$a0
}

        
