rule Win_Downloader_Dadobra_152
{
strings:
	$a0 = { 0fb07ce6e2be7c62fde5f7efd4e2f8547e1c327268def17fca588ff6a41bf6c2cf1f07df87158f3224c9ffab6968f96ae146fce080fc56dd74f989cde6a1ffe7aaecb78eb280821483c1a7c202fde7ba2b9ffbae84b2bcf99a86dc4b5d7b12734369908d1f0401e2eaa6abf12575a3bc681d286653e12a0c74d0d17161b2fb83a90ca960e7e19e8d5dee7a4e }

condition:
	$a0
}

        