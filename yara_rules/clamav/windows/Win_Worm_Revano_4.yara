rule Win_Worm_Revano_4
{
strings:
	$a0 = { 76617272656e6f76613d303b66756e6374696f6e72656e6f76615f636f6c6f757228297b72656e6f7661636f6c6f75723d5b22626c61636b222c227768697465225d }

condition:
	$a0
}

        