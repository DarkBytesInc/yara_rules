rule Win_Worm_Klez_1
{
strings:
	$a0 = { 2d4000bd08104000e89eeaffff80bd08104000be7d2d4000e849eaffff6a00e83500000064756d6d792e65786500653a5c77696e646f77735c53795374656d33325c644c6c63616368655c6464642e65786500ff254c404000ff25544040 }

condition:
	$a0
}

        