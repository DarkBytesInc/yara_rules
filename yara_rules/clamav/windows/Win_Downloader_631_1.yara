rule Win_Downloader_631_1
{
strings:
	$a0 = { d33f4360763f6ff8d65d5ace8cee27c399701c440d20e19d62e2bbe4527069023ba473cfdd422e01e90a6cf9422e033b5ddcfdae8b63929d18ad282c7ffeda35c8b76bdd2f3deeca479ea543f091ed5b63d1ffad38cc9a9bb760fb92919a97 }

condition:
	$a0
}

        
