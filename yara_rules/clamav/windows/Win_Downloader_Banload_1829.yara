rule Win_Downloader_Banload_1829
{
strings:
	$a0 = { 08aeb9197a165afe0754657f28e3dedf1913bcc638267e9ab0c90eb4fc4539f69f5bdacecfa75e993ca8b1043a707c931663fbe4142dbcd06bb470aa6fb94f3ca495c345f656384076d44ee03194f0a8ef8e732fe7c19d7e7350d3923b0b6e65ec4a151f886ed2bcfe }

condition:
	$a0
}

        
