rule Win_Downloader_961_1
{
strings:
	$a0 = { 84b1960dc5efafe5735bd8322b4eecb59c20ca0a6d7b9ccffafcfafc14e752b21a3e9f7808d7be03c673b78b096d63c41d222953c2867b082d3ac62ecbb8b29ba0046d930d98c5a9ca00414374a62b7d4a832c149830be16465a2023 }

condition:
	$a0
}

        
