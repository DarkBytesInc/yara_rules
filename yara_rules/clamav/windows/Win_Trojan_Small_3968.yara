rule Win_Trojan_Small_3968
{
strings:
	$a0 = { 0781efff65890789fe8d9f7c04fe7f81eb0000fe7f6a006aff6a006833030000ff15f8??400005f9df23bf0304240107c10f105883c70683ef0239df7ed7ff }

condition:
	$a0
}

        
