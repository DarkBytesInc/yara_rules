rule Win_Trojan_IRCBot_278
{
strings:
	$a0 = { 39efb2d818c54300f226c77112847852b5fb09f648aa9fd4725448e6b3e10c5a60c3a548e38c4b19dfede0a7f7f2ee98ae45edb7a8945a92a0737f40be3b790a4e5975bd4acf0289bf5834cba18f5187 }

condition:
	$a0
}

        
