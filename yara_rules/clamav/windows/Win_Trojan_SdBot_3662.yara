rule Win_Trojan_SdBot_3662
{
strings:
	$a0 = { 411b79f8f86f88e820182aca3a48998bb01750020947663a0aa4a82a488ce8e57129581dc22d00e7b5ca85d676b6ab57f7fec50a981540eb3a655f5564ab3c794ecf6bf80ca1b6cefbe6bdbc37c4 }

condition:
	$a0
}

        
