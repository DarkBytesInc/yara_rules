rule Win_Downloader_565_1
{
strings:
	$a0 = { effaffff0080c614c685eafaffff3280edd480c552c685e8faffff6980ca3380ee2cc685e4faffff64c685e3faffff6180e63d80e5175580ea5a83ec048dbde3faffff893c24ff154c5001105d80ea7c898563feffff8b8563feffff8985a6f9ffffc68532fcffff2ec68536fcffff0080f10dc6852c }

condition:
	$a0
}

        
