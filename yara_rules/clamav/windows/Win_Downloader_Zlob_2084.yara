rule Win_Downloader_Zlob_2084
{
strings:
	$a0 = { 91c36f3037c9d004f92140754d5ab6ee402a40728e8ae80f6481195d80fde2bea3018b23f643cef7252089421921772d62e4af9b9b2d5f1ceeae9e62b5517323ae997c6ce4d7efb2dc261f59875570923118746683356fd07851435df66c5c33ca72d6872f728a7f48b4ae8e961acd0f284b80a4205f01feb7fc6ce8575535d84d3de77e8fd6558ec1a23adc7d7ddd16 }

condition:
	$a0
}

        