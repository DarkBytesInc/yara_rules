rule Win_Downloader_557_1
{
strings:
	$a0 = { fdffff0080cd27c6853cfdffff5080ea0ac6853ffdffff63b62bb57cc68547fdffff7280e2f2b12bc6853efdffff6fb671c68545fdffff4680f57480c520c68548fdffff73c68541fdffff7380f2d1c68544fdffff325580e1cf83ec0880e5598b8510ffffff89042480f16b80cef38dbd3cfdffff89 }

condition:
	$a0
}

        
