rule Win_Spyware_Banker_3335
{
strings:
	$a0 = { a20768663d01aaffebae0693220539047312ea39d4c5bd89eec0dbf2423313df4ed0bb5596e8920bf1f996138cfebb788ad89c3a0fbd1fb2fa80af1d2877419d68bb8ea1a7da44323b6a751b4d7517933a5f96bed5 }

condition:
	$a0
}

        
