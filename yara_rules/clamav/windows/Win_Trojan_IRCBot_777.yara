rule Win_Trojan_IRCBot_777
{
strings:
	$a0 = { bc5ea757c972192c7ad427cc5ef613b2ec688e31bf67404e8a5f6a10792200000000a25c10213a226c7b937c06cb9e80f5b1a43eedadd2f4e9b283c71b92ae68818d0000000051b3a403252a8a22f8f0325af37dff9221aad21df59108c82e62838620c7e34600000000affbbb72e20e733e81a025ba47ae2b25f153f675acd242aaf425ed4309041bf60000 }

condition:
	$a0
}

        