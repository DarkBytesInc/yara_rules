rule Win_Downloader_Zlob_1721
{
strings:
	$a0 = { c488faafa272d3c00486bfe066741705ba99ad9f10fc1e36c6af67cff7b9713d204b35d930045fbddef566aa3e226ee805f6b2ee4cda6a5c8eb73f588d7afefe9c3951a5c9d136604e49e120d5ffa2f7ecc48a01089ecf132b35 }

condition:
	$a0
}

        
