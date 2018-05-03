rule Win_Ircbot_Jane_1
{
strings:
	$a0 = { bdf6a4289f9bd542107b745603d46d97c39de5dea41c739d86394b613a998981992e6b79944f8f30010fdbaf0ed7b56a }

condition:
	$a0
}

        
