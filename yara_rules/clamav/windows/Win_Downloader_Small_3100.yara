rule Win_Downloader_Small_3100
{
strings:
	$a0 = { ad1b3ba63c37097d7d3eebc8cee15524ea415001cc87e6601fb57f803e7b1332968d006e09fb570625b9cc0b8bf7f2c80633583698765b06e9b230e1daad1432b018b40b112d6f0eb5a93510ce6b8592fd086604d2756b11d475c24664417473a55861261c9c37deab813e17ff0f68246766f103a66b91fc7886de9319b47d07ca619e30cd375538c09affd0eda6d77a6f944516ceb5 }

condition:
	$a0
}

        