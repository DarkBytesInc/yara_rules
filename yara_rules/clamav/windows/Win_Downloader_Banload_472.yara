rule Win_Downloader_Banload_472
{
strings:
	$a0 = { aa687bcfb1b7ee7b65080d4f6cc9b307361272f88d565a75a2527d03e6fcb8e96b1ac912c681a484bd45c31bdbb48fce8b0782682b84a3a0f2c65ad1bb5dfda5e122d53b391a413abb0ead833eb33807719f575a }

condition:
	$a0
}

        
