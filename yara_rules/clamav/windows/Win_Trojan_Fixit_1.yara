rule Win_Trojan_Fixit_1
{
strings:
	$a0 = { 05004572726f720034380d00c974473d9a383800ae033300436f756c64206e6f7420696e697469616c697a65207468652073616e746120636c61757365203d5d204f72207965733f203a2900473ddf374438f4523549ec3535499a380800f8030300633a5c00c311e537 }

condition:
	$a0
}

        