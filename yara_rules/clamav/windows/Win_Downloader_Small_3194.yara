rule Win_Downloader_Small_3194
{
strings:
	$a0 = { 3fdf014f3eaa2756207f70c95eab3cb1d995e1c53f5ff70b04566111ff55700ec9a77244c067765cca5557f1bc32bfccc2a67646d3475454b0da975d84b8533fe2a676c53456 }

condition:
	$a0
}

        
