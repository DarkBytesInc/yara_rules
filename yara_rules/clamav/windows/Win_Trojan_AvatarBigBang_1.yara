rule Win_Trojan_AvatarBigBang_1
{
strings:
	$a0 = { e90000e800005d81ed06012bc9b404cd1a81fa01017529b801028d9e5d02b90100ba8000cd13c686780200c686880200c686980200c686a80200b403cd13cd208db634 }

condition:
	$a0
}

        