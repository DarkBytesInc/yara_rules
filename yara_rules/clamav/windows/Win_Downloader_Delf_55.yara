rule Win_Downloader_Delf_55
{
strings:
	$a0 = { d0880c696131303230312e475db0a1e01909b8756f6c2e6d2e62a2026036722f676d702e6a7067ffe7ce9115d8eab98ba2fd65200c3a4ab0d70373eb20deccf82486c54ef805a0c859785b3393b053d90282a55287d6dcdf85884a0c6a0af1d8eb0e4820 }

condition:
	$a0
}

        