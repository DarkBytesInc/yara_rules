rule Win_Spyware_Banker_3463
{
strings:
	$a0 = { c4503cdbf2ed389b6a109a84b90e88c4a5f8c2aa4d5ba803ab17a30c42098718edd88906e8527b08d8c1cbd08fcdefcc0870613011691d9fe2fa4b8addb19c0ebc5d4b95b31905e6132b84e51add39fc288b7ff78168db36b95c92e291cda4 }

condition:
	$a0
}

        
