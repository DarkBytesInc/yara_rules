rule Win_Trojan_FakeAV_221
{
strings:
	$a0 = { 8d3dd34b40008d0d855040002bcf83e909e801000000c35d81ed794b4000458bd58db2d34b400083c60333db3bd9771e668b460386e05646ac5e8bfe474747aa8ac48bfe47aa83c30983c609ebde8db2d74b40004656eb1d0003000056f14c0000000000ccccccccccccccccc39c2339821c00000082c7c3c64b400001009000 }

condition:
	$a0
}

        