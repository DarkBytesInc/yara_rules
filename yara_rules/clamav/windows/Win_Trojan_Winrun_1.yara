rule Win_Trojan_Winrun_1
{
strings:
	$a0 = { 6f206f66660d0a40636f707920253020633a5c77696e72756e2e6261743e6e756c0d0a406563686f2077696e72756e2e6261743e3e633a5c6175746f657865632e6261740d0a406364202577696e64697225200d0a40636f70792025302077696e72756e2e6261743e6e756c0d0a40636f70792025302064 }

condition:
	$a0
}

        