rule Win_Trojan_Rootkit_27
{
strings:
	$a0 = { 6b56616e74695265616450726f636573730000000000080000002f86d18f2d59ee991ac830ac769b4db7ca7ec71db7475868f05e49f54c64fef00b587544add8a80ea88cc6d79ad084b9e4625f1897936c2ed7a944d8d0b376580b51e89642d72a60ed38 }

condition:
	$a0
}

        