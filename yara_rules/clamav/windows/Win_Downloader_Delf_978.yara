rule Win_Downloader_Delf_978
{
strings:
	$a0 = { 34502b3e36b76d589e1c6c7e758b503cdf8486122128635e9bd86f2638af28afa5fd73cb95ae2b94075ddad1e47d56b703554237e7c07cb6e04ba509d134443dd1b92636a929 }

condition:
	$a0
}

        
