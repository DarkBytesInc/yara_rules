rule Win_Downloader_Delf_1073
{
strings:
	$a0 = { 7b31e87276d46e2abddbdba8c4124a52dc03b599f5e36f412ab2a67b522f9e7d0b2012da70a95b711fa78228515186aeadd55a43c3481df73a6f51cd7c5215b2436b233b8bed304d9a4b08c3711bbc84dfda2e4e69 }

condition:
	$a0
}

        
