rule Win_Downloader_Delf_1067
{
strings:
	$a0 = { ec591b6b74b4527154e6e18910a3e985367e0ab58de59e019d53da640d8970aad8d42fd1ed480e1728c2559e4a9dd5d9b37d4ca5ba2bdda89c9d53a6e25b8f4c30b3aac87cfd73e93d902e87e42e44079ef60ecd78 }

condition:
	$a0
}

        
