rule Win_Spyware_Banker_1040
{
strings:
	$a0 = { 31e3b0c026c034fc2d78fef17056de86c9c23bdd4f3165ef49b1cffd7ae59bef9f35ef49ddb127bd2c461d0fd91259f663331be2e199bd070feb5852d7e4781747dd934ee962d4857faa0b4f99543af323cddbc9fe47f10ef481e04f83d86ccaa890a1c2c2def5876ce190322994202c7789fac84e6ad154f973c4617a0d4b099b9a737d29153e8bf6c2074102fbcda061c1e0a0d460 }

condition:
	$a0
}

        