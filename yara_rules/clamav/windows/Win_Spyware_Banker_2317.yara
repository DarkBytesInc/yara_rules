rule Win_Spyware_Banker_2317
{
strings:
	$a0 = { 752aecd5d3042ec7e35eb5713deb35c3d21b8376445bd4a012da0daa954472334caf223659a8b27cb05168a058167046ed44ff47b8e45b2923af19fb0b3043955ca7429569ad27bd0205143ed811e274049a3bc9aa849548e06e7a14e17078b4e8f97bf39b6b62b907a6eccae37e7ae61a4072dcc8194ae6b72a0387a934ceba }

condition:
	$a0
}

        