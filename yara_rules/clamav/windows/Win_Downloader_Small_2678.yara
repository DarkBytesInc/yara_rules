rule Win_Downloader_Small_2678
{
strings:
	$a0 = { 672e74787400006970662e65786500696670 }
	$a1 = { 7269766572735c77696e75742e646174000000 }

condition:
	$a0 and $a1
}

        
