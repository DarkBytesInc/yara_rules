rule Win_Trojan_SdBot_4471
{
strings:
	$a0 = { 9c84bf5426b16f1518041d7f4ed13d5bee7bd5d72894fd4cfdabc17ff6d1a721669c43cc30b76119145b44bfbc63ef594191d9158a04fb7fe6d197312715dfc98a3d85e73f59efbfea6dc5315e64c47b2413cc1fbfc69f518ce58923225dc4fd3f27ef99ea4129d45c84c9acac83e97be6ad5c178ccb89292a1c }

condition:
	$a0
}

        