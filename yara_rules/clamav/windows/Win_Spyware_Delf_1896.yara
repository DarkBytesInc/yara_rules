rule Win_Spyware_Delf_1896
{
strings:
	$a0 = { 9a7d0d5c54c7d5f7dddd0b2cb8caa2a8a8a8c4ac898826201ac185b8028bf881ac7c89281a1bd8a0216ae15e3509e8d29586cb8496f649fad85ff23caf3e26adb5be7d4863233169b2b0848f681344ab202612b5297a494a94eaa2c47dcf993bbba0319abcfe64ff73e7e3cccc993367ce7cdcb9bcdec469fc12b66c29 }

condition:
	$a0
}

        