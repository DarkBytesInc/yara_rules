rule Win_Downloader_Delf_2154
{
strings:
	$a0 = { 0fe73127c084bea3e85bd42d2b1385b012dd0590884a6e906cf6cacbb52dcba3bcf6597aec88289fcf5e6f761e8f17ba533871bfa5378f13ee9730cae02609dd967d5a1e12861aea4fb7307a2eb99d1a56a0b3bc16a42dabfd8e3bc45d9c1dd5105ee6fde32b1b603ad03238bef91b55 }

condition:
	$a0
}

        
