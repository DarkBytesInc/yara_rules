rule Email_Trojan_Trojan_806
{
strings:
	$a0 = { 0acceee6e5f220e1fbf2fc20f2fb20ecede520efeefff1ede8f8fc2c20eef2eaf3e4e020efeeffe2e8ebe8f1fc20ede0f8e820f120f2eee1eee920f4eef2ee20e220e8ede5f2e52c200d0ae4e020e5f9e520e820f2e0eae8e520e5ef20f2e2eefe20ece0f2fc3f3f3f3f3f21212121212120687474703a2f2f }

condition:
	$a0
}

        
