rule Doc_Trojan_DarkStar_1
{
strings:
	$a0 = { 4966206e726d616c2e4c696e657328322c203129203c3e202227736537656e22205468656e }

condition:
	$a0
}

        
