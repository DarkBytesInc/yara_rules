rule Win_Trojan_Inor_32
{
strings:
	$a0 = { 6c656e6774682d312c3129293b646f63756d656e742e777269746528756e657363617065287429293b7d3c2f7363726970743e22293b3c2f7363726970743e3c7363726970743e6b6f6c3d303b66756e6374696f6e206e30303028297b6966282b2b6b6f6c3d3d33297b673d22687474703a2f2f }

condition:
	$a0
}

        