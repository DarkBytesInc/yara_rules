rule Win_Downloader_Dadobra_224
{
strings:
	$a0 = { 434387b712a40d9cf8db22696663bc6d98b345c85e86dad86edf2399ac6cd7c8d94ed14d359c64c6d3c8b1350759768e5701c5756324d6b0b9a8d5a4e46e7baaadd44c1c5d6ada834099c3e9e75e04505eb423ac5e3fd824dfed }

condition:
	$a0
}

        
