rule Win_Downloader_Banload_602
{
strings:
	$a0 = { dbf267d4bfd187107d7d936001645cb11f365d39e7bdad2415e9d8227893c12aebb078b398a6f9262cc2213986f7f5da848067f435d2ddfd701d35d521365464ed8824e3 }

condition:
	$a0
}

        
