rule Win_Trojan_Bancos_1041
{
strings:
	$a0 = { cb647591863ca9abb1e4171392b2b628675be070ff2de5b6f76111f312ad398e0785b16343ea7a51d30afbc924998edefa6f5cea55881cc912046eebffa0cc20587312a868fb95338a9e5bb83ad6f0302f4352f7988c6a2d }

condition:
	$a0
}

        