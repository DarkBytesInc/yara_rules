rule Win_Worm_Bagle_21
{
strings:
	$a0 = { 73098b8d13a52057d632d7933bba0d3aaeba0d0fdc3b1f9e6ef1971ea3e3cf58c46e5f5e9069eeb515e9c32e8e5635783ad3ded02e9bbea79c37d1fd24ded188729cd79c53c11c5c8aae8a82b3db74aabecd267bbb852b5e2f4b875c641b4e8a1ec87e9e751d11f39139fdafbd78317ad20abb }

condition:
	$a0
}

        
