rule Win_Downloader_818_1
{
strings:
	$a0 = { 80f150152d749916f6c8f7f0d31845231942c9369b63548161f23cc505b43e38056c2ca60f56fa801f1f008a24fbcae9da57c5c78f9a12fbeca0d6d9b6b3a7f22f56f82c206d3101e06c1feeb8b5a9353717b05498ed8f0c14edc39fede314d5b986833bb579dbf25005ae4c32832eeb51b43445caf5492a1a29e243 }

condition:
	$a0
}

        