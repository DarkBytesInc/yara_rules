rule Win_Downloader_Agent_31661
{
strings:
	$a0 = { 77735c43757272656e7456657273696f6e5c496e7465726e65742053657474696e67730039444c522d4a534d44554339342d504538442d346263382d413944332d4d43334a4b34354b4d463931000000202d6100747200004d6963726f736f667420496e7465726e6574204578706c6f72657200687474703a2f2f }

condition:
	$a0
}

        