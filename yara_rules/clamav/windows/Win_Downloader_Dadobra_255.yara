rule Win_Downloader_Dadobra_255
{
strings:
	$a0 = { dca7d4a1b723edbea091f54f6c7260b4f02dedfcf8aff207b5aebb8b2523b586048e98b1aac062469d12bc8d046f3570bb8fac63e4dd52317de14ab20f686b9550fdbfee9111783002b7e40771c55fba42da533aa7e2d67c680d }

condition:
	$a0
}

        
