rule Win_Downloader_Delf_1085
{
strings:
	$a0 = { 434e75ebb850584100e855a5ffffe8a0a1ffffb8e05b4100b9f08440008b15a05a4100e813b9ffff6a01a1e05b4100e8ffb9ffff50e8e1fdffff33c05a595964891068c18440008d45bcba02000000e84fb6ffffc3e9c5afffffebeb5e5be82cb5ffffffffffff170000005c73797374656d33325c737873657276 }

condition:
	$a0
}

        