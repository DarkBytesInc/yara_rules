rule Win_Spyware_Qukart_3
{
strings:
	$a0 = { e731bc168ac24a55414b1a944ecece10b232bc6acd0e46c5a60252954e97ca10b636bc6acf085af84ecec06d43c1c5a14fce436afb36bb6ab1a623050cce2b128b8c4318cb32bb6ab19eab6f5fce43168ade2b56ee8c4318cb32bd6ab19eabd343ce4318cb32bd6ab19eabaf41ce431ccb26bb }

condition:
	$a0
}

        
