rule Win_Trojan_SdBot_4055
{
strings:
	$a0 = { dc0f067f026b6a815f70ddcde1b0fdf8a298ff3c394388625a1e7a90e368af975a8ae48556482ad6ac02ce42138b0f9f3ddbcccdb5e68c3c3cda6f58e09cddb2b5fc9c4346985dace653584b589ac655a2b4951637dc }

condition:
	$a0
}

        
