rule Win_Downloader_569_1
{
strings:
	$a0 = { ced7c685eef8ffff6480e1df80c1c1c685f0f8ffff61c685f4f8ffff3280c1ab80f203c685f5f8ffff2e80f15180c98cc685f6f8ffff6480e584c685f1f8ffff7080e17480f15b5583ec048dbdedf8ffff893c2480e250ff1548a001105d80ee1989853bfcffff8b853bfcffff8985e2f7ffff80f114 }

condition:
	$a0
}

        
