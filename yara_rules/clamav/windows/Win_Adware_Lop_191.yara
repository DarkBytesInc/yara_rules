rule Win_Adware_Lop_191
{
strings:
	$a0 = { 66181a25c69f7bf54efd6a4661dca5e40df1d50764547a5c83fff420248896107a2b30290f90106172967ab33e217092b3fe368e14faaffec337386c }

condition:
	$a0
}

        
