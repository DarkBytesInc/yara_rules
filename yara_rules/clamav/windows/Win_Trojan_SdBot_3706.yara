rule Win_Trojan_SdBot_3706
{
strings:
	$a0 = { bdbc6681101ed9e0a16b6cd942f771c47f4e36acda29a06f4d8359bfb4361af2fabc7a2911f53f7857c6bce586abaed09ccdde44ef18f35fdb22812dd1f4e6b8e40d0a8a90ec9ff5bce0b5860799e8376dfeb3f2d006d69bdf733804efb485f3b3528b3181b0dffc9b50c83755bd }

condition:
	$a0
}

        
