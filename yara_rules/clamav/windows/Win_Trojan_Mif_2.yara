rule Win_Trojan_Mif_2
{
strings:
	$a0 = { 9c061e16e4408ae0e4403ae075f6205b204d6946205d20286329205353542f2f5648432000e800005d81ed2c01e82600eb3700b4438d96c802cd21c3b44233c999cd21c3e80f008d960301b96701b440cd21e80100c38dbe6d018bf7b9fe008ab636013035a4e2fbc3 }

condition:
	$a0
}

        