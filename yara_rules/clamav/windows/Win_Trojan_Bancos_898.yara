rule Win_Trojan_Bancos_898
{
strings:
	$a0 = { 6be20e72b366ce2cd5dd0cce244897cf02ad328bf428399d91059fdb81637cfb0a2bcc292e5fd6939a2e12ed76c933564c552dc1d7685b34f784976516468d1fcc287cd618e25b9c6cd7be23ec76 }

condition:
	$a0
}

        
