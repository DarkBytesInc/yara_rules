rule Win_Downloader_Small_2526
{
strings:
	$a0 = { 90552c9589e5b6f981ec9400000081ecfc0c000089e380f1408925a8524000a13760400080c589898360070000a13b60 }

condition:
	$a0
}

        