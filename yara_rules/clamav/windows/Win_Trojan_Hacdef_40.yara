rule Win_Trojan_Hacdef_40
{
strings:
	$a0 = { f7c42a6e5f3fc3b5d745bc8c95a5d23304624178e66eacfeb401e8ced59fee76457848e3c352607465e19df3afcb4d2ff0b27f6f8eba42086dc67647c796f43b7958296605c5dfee3aac2df227926cddd5fa19069714a9ea35b14d34e72c3ff27dda472ddf33e010d3afe3bfd9a72cac43ea05bcdbb3cf4657211e05dc799668987fd359d93903c898fe5d0903128b78253ae9ae8924 }

condition:
	$a0
}

        