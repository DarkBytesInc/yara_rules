rule Win_Trojan_VCL_36
{
strings:
	$a0 = { 1e4381cd21bc0213beaa02cd2e508cc88ed88ec0b9130051e8740059e2f9ba640006b840008ec0268916130007b90500e307b8070ecd10e2fc06b85000 }

condition:
	$a0
}

        
