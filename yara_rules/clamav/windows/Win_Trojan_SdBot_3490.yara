rule Win_Trojan_SdBot_3490
{
strings:
	$a0 = { 0be98188eefea7a1c2a0039a82a7f343c978eece8234cd138f6456562151a8c36e169c5b1ea34a01c0fc9203c01016001bcae8936318098d923a39535f647372024ba8d12fd0ed9f0ffb0d21d7d26c4efc45148762e1e811429d279e8fc30288969b680891d108c7588f59d27ca9f7756efc819c4f24 }

condition:
	$a0
}

        