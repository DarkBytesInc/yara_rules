rule Win_Trojan_NSIS_20
{
strings:
	$a0 = { 9a805c696e6574632e646c6c00fd99805c67756164333733312e45584500687474703a2f2f786961 }

condition:
	$a0
}

        