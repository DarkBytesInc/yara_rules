rule Win_Trojan_Mybot_7751
{
strings:
	$a0 = { 76053c2e4269bad0c994e9fe79301a2dc1ecadd4ccb38460e3f89626c59b832664bdcb045a16d3b1f2454006120632c015ad5fe0832dcb9759de95ed3b00eb1e2f1f15dbc5818edbf85c1a714f962c74371221eda0bfbf91c6213a8ecbad966d4b93fe6c7021 }

condition:
	$a0
}

        