rule Win_Trojan_IRCBot_662
{
strings:
	$a0 = { 76d77b98ffec597d44cdcc41d81690f3550573a2997f6eea89317327eccbfd93941a035779b8aff44db72c432b6cd92634bd2de6a1206d9943303de7a1bb7b35fa49f13fb6cea5e821c2315a620ff69cca86bebd13227af956b85e811de2228a26a8f3c3819b8ed71bae6d78ced5094b14e31d593e9c9e61 }

condition:
	$a0
}

        