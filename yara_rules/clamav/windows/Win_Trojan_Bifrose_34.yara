rule Win_Trojan_Bifrose_34
{
strings:
	$a0 = { 251d265fd37820356c0e9a1c1f37d9473a7c8911e755ce868ee0d5127b3c3040d61f79185e52d0fcdbb6f020b57397f572de57c272429f2e4cfb0f5babc0d9e7249fb1c77adff0a8308d94e97b6e159267234b3741373bcc0285572569a33cdb75b8dea72a59c2b61044bd6b1ea6ee8cc78cc19ce78e21ef219d043c30533501b4fe19f4ee02270c65145f077766436a529d32ba9ac5 }

condition:
	$a0
}

        