rule Win_Trojan_Mybot_8340
{
strings:
	$a0 = { a3fab019d750d0ce848c63a3b8ddd5cbe209bb8ce7298c4c30a2c8f69a505b1d1d3b7c50a2886377933a73fc06036764b003600c6a2a145f36eb653e6d81a6c4bba60787626ea85eb9d5dfe4b658c57e }

condition:
	$a0
}

        
