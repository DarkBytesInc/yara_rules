rule Win_Trojan_Bancos_1103
{
strings:
	$a0 = { 6fa4ddb51d10b037b5b135fdc165851b034d5c24497ee08cff87877bd263b07987ce07aa7a09063664bff65e60cd3f6d04e91e9a140ae9b77fbcedbf94f65fa3281e5e40e76b2728a117f6fb4bdc2ec3ac0d37df3ef668726ddac64a2b7e61d037a96b38711d }

condition:
	$a0
}

        
