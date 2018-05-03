rule Html_Trojan_Fraudpack3662_1
{
strings:
	$a0 = { 8570fdffff3b8dc4feffff750c138decfcffff238d0cfdffffc9c39090909090558bec81ecec02000029d201c2019560fdffffff85a8feffff3995f4fdffff751bb8320b00000145d0318540feffff01850cffffffff4db885d277034221c20b559431d2 }

condition:
	$a0
}

        
