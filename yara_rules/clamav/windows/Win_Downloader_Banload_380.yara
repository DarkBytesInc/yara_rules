rule Win_Downloader_Banload_380
{
strings:
	$a0 = { 1fcbaf6e89b925edff86b35e358347d7602d8156785af06788db74123341ca84b4fdfc15db89ad545e28fbc7fa53041b4a751de74fc698e5932adea8151cba1adefd3ac18285802af4df80b5ae7f6b3a13e0b8f1e70020f0eb7311fc864636e76fa29a52 }

condition:
	$a0
}

        
