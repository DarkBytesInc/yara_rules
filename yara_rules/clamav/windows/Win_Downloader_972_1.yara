rule Win_Downloader_972_1
{
strings:
	$a0 = { a56cf1c80530c4fa8cb2a380b9712c1ee823c351e5d83e008d2aa08c34c24d932d3eb7f4c9fac57a93cb2dcef6d0bbfac4d839c68f7d149d93babd99e364dbb6b313c13ef637d079c71fc14370c561debc60f1f00074b6013ebf87c5 }

condition:
	$a0
}

        
