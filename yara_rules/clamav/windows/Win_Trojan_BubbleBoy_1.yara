rule Win_Trojan_BubbleBoy_1
{
strings:
	$a0 = { 2e52656757726974652022484b45595f4c4f43414c5f4d414348494e455c536f6674776172655c4f55544c4f4f4b2e427562626c65426f795c222c224f55544c4f4f4b2e427562626c65426f7920312e30206279205a756c7522 }

condition:
	$a0
}

        