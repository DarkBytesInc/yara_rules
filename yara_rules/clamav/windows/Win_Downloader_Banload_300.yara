rule Win_Downloader_Banload_300
{
strings:
	$a0 = { fcd840e50b5bc670cf7d31643781abe0daa1c9eebb2bee9a9b44c22bc2c1165f10ae569af7dac6d8ae33e01c01329d877deb650474944290eaa614a085c919089b152ada5a5d92df4bdd82e015788352d087dcfda7b72cd933f87e87519e789bef5afde421b7e804ff1e89c0c4373037636d6ecef4fc38e6e27cb9bc14081c1490e2267b10c6fd0961357fe700194acc06fd53e3f22b }

condition:
	$a0
}

        