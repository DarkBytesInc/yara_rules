rule Win_Downloader_Istbar_102
{
strings:
	$a0 = { 732f6973747376635f6164735f646174612e70687000000000000000000000006e6f0000d8f15030b598cf11bb8200aa00bdce0b000000000000000025442c33cb26d011 }

condition:
	$a0
}

        