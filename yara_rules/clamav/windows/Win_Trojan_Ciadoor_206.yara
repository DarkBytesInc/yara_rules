rule Win_Trojan_Ciadoor_206
{
strings:
	$a0 = { c06a649d00082ceddeace9fc0f226faa780059fc5bd3aabe2781fd2103101adabdbfe30176c589eac9f01cac80fabe341071748f053bcfa0215664b66a61bb34a7de3c55aed8f14037aaccee65919845ec2c01b51cabc80e09c547f1aedccab1fdfae4dc }

condition:
	$a0
}

        
