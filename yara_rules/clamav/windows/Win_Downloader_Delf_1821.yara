rule Win_Downloader_Delf_1821
{
strings:
	$a0 = { 9abd0f5c5455fa3f7e67e602038ecea098a6a854538a6882d80a0ee6280c228a8efcf77f24101aa90bf78a15c8b0039fb89c28b63f5bfd6a3f9bab6dbbd66797b636e9cfe6c02848ba8ae82a8aa5697f2e8e15092ba392f37b9e73cf0c68aed6d797ccfbdcf3e739e73ce739cf79ceb9e79ccb1bcc9c2660dec68d8579 }

condition:
	$a0
}

        
