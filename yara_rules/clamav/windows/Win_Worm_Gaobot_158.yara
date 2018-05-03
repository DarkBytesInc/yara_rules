rule Win_Worm_Gaobot_158
{
strings:
	$a0 = { c8b263fd7bdbd2171e9feb0f24c11ac7ee55778d503804cccbf89e8a8d1bb1ef07211987ae31ad736dfe22e559ee0dfa7eba3c28634bb86eb44c16f7360244e1b49fb0533835e03dbc43783b94e4d2227fbc10367e43cae0ed23f6964b3d568c98d37d4a9b9d65caddfb950c9aebbeaef79cd91377cc6f37a0ee555a }

condition:
	$a0
}

        
