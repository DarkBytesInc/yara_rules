rule Win_Downloader_1048_1
{
strings:
	$a0 = { b142186f19e5b18d5ce298b5f92dfafa27b8a78293ed6c450113f0b8d5054da2648afdd41834466f008eed8adcda36c6b1aaa79509f4fae36463a96e2af003f205c59ef0c14decd9f6faeffd8a3a1cbc0f0277ee15c14214b909fefa }

condition:
	$a0
}

        
