rule Win_Downloader_277_1
{
strings:
	$a0 = { cc971bfb3fd054ee6766bdb8b307cd8ce3ab96522acee4c3bb65928a62e5580f511b27dd1e7d37cec6839e99946949f9b509751011461b6a9db741cc645ee269b27ea5a8ab9625d775a2fdaf7396 }

condition:
	$a0
}

        
