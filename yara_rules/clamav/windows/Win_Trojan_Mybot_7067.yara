rule Win_Trojan_Mybot_7067
{
strings:
	$a0 = { 87536c763ef55fcec324bd37dd9abe21b2215c43b7c5b95c96dd8e51bdd34b754637acf9a99849a0504f2b17ef384d344b42893a28e5fd3ee0098c4b8ee88123861607412ec0fba3ebc700d4ce2ff1b9c25f3ff8bf4d128ed516bc0967bc70e8db3f79fcb7f121773d5491d8aeab2a16cbb734ea78688eaff330b154b81fc9c4a1ac6b4a5b7c659adf30befdb98b672a01c10edbdb1b }

condition:
	$a0
}

        