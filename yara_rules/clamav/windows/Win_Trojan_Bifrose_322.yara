rule Win_Trojan_Bifrose_322
{
strings:
	$a0 = { c3730a5ccabf15ebdc8311dbdf730c2181187e3d20cce6fed2ec5246f9d4d455b5d2505ef721d106f473c06e728c9647cec1565e29a6ec02cc43e357c9a644c765d958e7ff5f3b57d507d759b03fa47b8def201d41bce85a6d81195c4554498369ddf2dab8ef03b3dac2caa1442b1d523a5a824fe19f0b73dd81e44eaad72357a985041b22854d7eb757241e }

condition:
	$a0
}

        