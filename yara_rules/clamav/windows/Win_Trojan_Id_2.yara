rule Win_Trojan_Id_2
{
strings:
	$a0 = { 6563686f20225c7834315c3131345c7834325c3130315c7834655c783439415c303734625c3136325c303736223b24783062203d20402478316128293b24783063203d202478316328757074696d65293b24783064203d2024783163286964293b24783065203d20402478313728293b24783066203d2024783138282253455c3132325c7835365c7834355c3132325c7835665c3132334f5c313036545c78353741525c78343522293b24783130203d202478316228293b24783131203d20245f5345525645525b275345525645525f4e414d45275d3b24783132203d20247831392824783133293b24783134203d202478313628293b24783135203d20405048505f4f533b6563686f20225c313537735c7833615c303430247831355c7833635c313432725c303736223b6563686f20225c7837356e5c3134315c3135355c313435202d5c7836313a20247830625c78 }

condition:
	$a0
}

        