rule Win_Downloader_Banload_689
{
strings:
	$a0 = { 6a4c0d62a18d9267f4424d713e2ed8ad1d378fcf39c7d23851b70b42896410531ea4e22df45dc413ad6239bef4bed96880ba00a3a0c0207b9d27c93823dccdf0e68d337cf8823670bd2eba2cb9d7b351aad67e496efb2e90a422 }

condition:
	$a0
}

        
