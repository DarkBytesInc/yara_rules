rule Win_Trojan_SdBot_4444
{
strings:
	$a0 = { 6b65acbf37136ce389ac8421e1537931e6b5559ec25b4445c748841ad31b92d5c9034bad7ccd6a8e562644449d82e09ff060095e3df55fd60f1cb05bae68c1deb3f37583193e599e0ffcb856b5baa32d783c47f2a238d61c89275db7c05ee83113137a6335970b4c28258de2264fa981d08073a53d7cdc46c51e91fc6c62143d85586721d0e94e5f7f616bb87e30fbb3 }

condition:
	$a0
}

        