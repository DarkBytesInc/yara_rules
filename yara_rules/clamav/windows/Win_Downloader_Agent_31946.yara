rule Win_Downloader_Agent_31946
{
strings:
	$a0 = { 0b58521c5dc9e603afb98e546fdf45f1194dcfbc6fe1f9f41d8826912be5c3003f2b5841e9b30017f1f3bb7bb37ae992163e72bd9dcf405bae983faf3e563d85b403aaef4052efd28207e2cab28da76a885de0bd62e153df9afb }

condition:
	$a0
}

        
