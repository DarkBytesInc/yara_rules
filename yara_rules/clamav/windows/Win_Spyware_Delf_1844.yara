rule Win_Spyware_Delf_1844
{
strings:
	$a0 = { a881271001bbeaa9aba0e4cacfc7c0ce9e9e01c00a0397d7f1e3fde888dff8fced0a80115683a8827b3d151d0972c4e0c38ae130004e386d6c23071c0201001667300460acdfa124d19900ce8a25be57102882090340283b69524e5f39cb6b460268b02369484f4b02b05c58278985237861801e1541651f009e906ae0 }

condition:
	$a0
}

        