rule Win_Downloader_1001_1
{
strings:
	$a0 = { cfd5b824464baae31c39198c418364c9acfd17b867f3acfd1020bcc2df1de2c8edc60f9d7cfa82fab31174914b227efa09808b726d23acd76bb101adb5a8e7f6e548ba7dfaf25b4fd108d1367f276c63858d558c102a7aa08151db59 }

condition:
	$a0
}

        
