rule Win_Trojan_Rootkit_73
{
strings:
	$a0 = { ffb5e8feffff566a316832343400e8d7ffffff8d8d5cffffff51536a35568d85e8feffff50e86cffffff558bec81c4f4feffff6a006a00e828efffff0bc00f84800100006a00e80af0ffffebf76a00e807f0ffffe808f0ffffe809f0ffff50576833310000e8a3feffffe8feefffff6a37ffb510feffffffb5ccfeffffffb520 }

condition:
	$a0
}

        
