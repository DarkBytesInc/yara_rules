rule Win_Downloader_28852_1
{
strings:
	$a0 = { 8b8538feffff508d8534feffffe8b9eeffff8b9534feffff8bc659e87fe4ffff8b06e850fbffff6814564000ff366820564000b86c7f4000ba03000000e8d1e4ffff6a00a16c7f4000e805e4ffff50b86c7f4000e842e6ffff508b0750e8f1ebffff }

condition:
	$a0
}

        
