rule Win_Trojan_Hupigon_1675
{
strings:
	$a0 = { 68581bc1d5ed9bd627a395749883e2e3c5a784f6d01f5858167fcb50f4bafc7db0890d5f93cd0ea586d1f65c72f2cce89e59d6d271fcfe964cc0f6ebe2d727fdccbf74166ba316079d1e254f62a77573bdab87ffb0bbfa97c3b29b04b3f95d }

condition:
	$a0
}

        
