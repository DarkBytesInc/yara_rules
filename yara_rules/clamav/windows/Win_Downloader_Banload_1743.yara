rule Win_Downloader_Banload_1743
{
strings:
	$a0 = { deee1d4ead64f42a066f2f7d87dcccb039a94f90dee9e58d37f4073279751b218eebf44e9039b5f443cd71c75bf3dad0fa0873196e29ee57d0acdee45d5c788330bff82cf604f8f9d740ae7714aefa1e5eb5e81b5c9224ada4e87c4f03699fe6c63a66fc8f36092e646058c0366c3af43368ca614157d8016d0eeeed6b42bd5443ef26464bae4175dcc6c7ba }

condition:
	$a0
}

        