rule Win_Trojan_SdBot_1616
{
strings:
	$a0 = { 6a8b404a92a3f7c546d18c14953237b69d0d8f47b22259ef7d432808c474312f9301e54adc197234595f2d63aca8c4a9f6c33e29d449c0fa6d63b8372f33030e32ae4323c1fdc117f7389c82f2d9da3f }

condition:
	$a0
}

        