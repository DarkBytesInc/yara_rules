rule Win_Trojan_Small_3969
{
strings:
	$a0 = { 8d3dff07ca0781efff65890789fe8d9f7c04fe7f81eb0000fe7f6a006aff6a006833030000ff15f8a6400005f9df23bf0304240107c10f105883c70683ef0239 }

condition:
	$a0
}

        
