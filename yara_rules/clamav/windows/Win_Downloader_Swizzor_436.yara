rule Win_Downloader_Swizzor_436
{
strings:
	$a0 = { 9e679d9e0ff84bfc9d969e8dfb0cd058ea48dc1ab443bc598abcf6f7300a034a87677bc16104cc3048f4b1d4fabcb1bea8a4ecf06d3f0a08d486f55096ec728dfac98488751a111150ca5ced0b36adc2153127c118b2f8bbe5cf }

condition:
	$a0
}

        
