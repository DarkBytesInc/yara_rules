rule Win_Downloader_Small_4894
{
strings:
	$a0 = { c07402ffe0686996dc0ab88011d02c45ace085adab244f574e6013a0ee45584543555473cb628ccb247a2768792e22b8702f8ebec8603208eeb10c2e317187e5b1330ecb6dc13600376859068bf46f6ee369c43769938c44725ff2d27cc343c01d16781e00cb5bbe8c43cf6e9fb86639192fcb273531372d925bb238bdb8a7da6db35824 }

condition:
	$a0
}

        