rule Win_Downloader_1089_1
{
strings:
	$a0 = { f1278cbf2acaf6605548eac90b9d900b9071f6b227db6a10cfc23b05924cc604e700b78ded633c5df10e6e2ce07b9eef85f2de1770e7690656b66a4e7d23c7fa2ab8a299e6fb1668b6d78feab9ebe318857ffbe4c6a22eeaeaac9078 }

condition:
	$a0
}

        
