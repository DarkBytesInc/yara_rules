rule Win_Trojan_Hupigon_651
{
strings:
	$a0 = { 351661550d16e8136cd093c226b83c4eab089e4a0244fa0cece2ec19dc78c54b9e94fe9dbe6bbc966367dbcdb327f4fe1c7018d2c6daa8b72a3b2df2f2e1198ba355c0b4c591654abf2d4f41b13953047c3dc3464ef0e950e2cd3cbb743ea15fdee69ba9f8b2a4ab8556c394afbcbfcfdd9c5d }

condition:
	$a0
}

        
