rule Win_Trojan_IRCBot_215
{
strings:
	$a0 = { 7313cfcc631082661c98be001ca4d7fd5d2dfb6fc6750e68c5a20584c19f4e7bc54cd8c2a59911aabaa2f145f1718abe38b1b2efa15721ec633ffbde0a11e8bd266f1f13d7ba2aecd2c7115126c0728e2df6284bb437be4a2a3cea56b1ea95fa83e98f35bfed020104 }

condition:
	$a0
}

        
