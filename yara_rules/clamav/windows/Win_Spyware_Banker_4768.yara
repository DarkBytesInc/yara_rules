rule Win_Spyware_Banker_4768
{
strings:
	$a0 = { 431e9edf93d670cb3cca52c77897779e37a3e7bdf791ece35a97781a57bd75302b24440947eb136635428834d2cb954b59d77a8ec86d828f81eed3b48d49163acd8ea295cf3a2bff0aa66ff428aff95b52067cf38e25933275da70fe1a59bdba588b2a19024926b6c8bd0ab2808a5cce4376b889fc6af46ed6ddf0977068cc40d7fd7921a4d56cdbd9735219877fa44fa0ff71715506 }

condition:
	$a0
}

        