rule Win_Trojan_Small_5295
{
strings:
	$a0 = { cc471a85a4fae14da7af094660b75f3a73ef5993ceae5aad4cbc49c5f14778c6a4af8a01bc507de1bc501ccdb4ef099afaf2529c67f95eada4bf09c5cea7f6d09cbf49c5f4501cf9b4ef094e54c509af87f963c55bba5dd5e4af8c05d09d82f894bf49c5f250de4064db2c935b7889b9945055 }

condition:
	$a0
}

        
