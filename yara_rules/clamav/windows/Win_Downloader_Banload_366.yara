rule Win_Downloader_Banload_366
{
strings:
	$a0 = { 6ee3924ffa0c465f175401734203c557fa2c9e4e7d441635fa23d8ba62b057a5fef641872ed5c12bd52f4ba7f2fb5390a2ac4fd4755d0ff6d357fb486e39150b1beb2addee2e450f5a9971ae8a6e247a8d3b12d15c440645f1d0af6ebe21c923afcb0467078aae9de8 }

condition:
	$a0
}

        
