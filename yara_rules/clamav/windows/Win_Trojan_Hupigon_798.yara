rule Win_Trojan_Hupigon_798
{
strings:
	$a0 = { a10b5c8d3cf4d7275269a48bc6fccbed73ea6c8b495ae34c4facdb27164de4fe7e4c896d73c9d945de9c2424ceefe4978fe5e7bcbcd76cefd90bf7362a8e4c48e5c60ac16af7210b80c069c6579c2afc82f4492e6edf14c576dc2cf08b072f }

condition:
	$a0
}

        
