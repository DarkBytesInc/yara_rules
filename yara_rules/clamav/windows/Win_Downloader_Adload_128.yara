rule Win_Downloader_Adload_128
{
strings:
	$a0 = { 6dc257d0fcf2fb2db71b46fb923e173fe5d9b6aab4e1a1d5055208b2bfede2f77b36ae5c977aeeb34f71aee924d5b024173666f744a22fc2640a3baa413b905e150761b795cd6fe72f5a3feae41e6acf136b16a1abd2a6e123fe363b15f1b6b5612da8b31f310d2a80f9aee1d311d600772336521fa92a1f6b1c6f3deff22e2acbf965e3121d27c215765267 }

condition:
	$a0
}

        