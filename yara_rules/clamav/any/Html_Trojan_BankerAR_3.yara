rule Html_Trojan_BankerAR_3
{
strings:
	$a0 = { 12613755c6f8fab0e4ac33523d6902680c0ab7d6ff2ea99d82ce6228a692e62129c9e1b52b2f50e823ccadaf2bda9d05c85202eaa4cb08f21d0cc639fb157e377cd2f2011483d54bf9e3c067a5a1b0d8a89a56d6a897a7b9465df18b77afafcd5e2effd3525b5ca8f16403a6d5fe1504 }

condition:
	$a0
}

        
