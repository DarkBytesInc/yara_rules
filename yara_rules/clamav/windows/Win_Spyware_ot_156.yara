rule Win_Spyware_ot_156
{
strings:
	$a0 = { 71eca0ff1b1af3cc3727acffe3cbecb3db5cb1ca7df409b34d575780d0a272fea83c416e6376e3915c86e21df166cac75c5ad2bd68ab0916aaa079e1f44c8cc0ffc66cb5ef127473ecadc41b7487dafc411dc9d7d8b24a279a07a4321d59543b07db026f21b243314f }

condition:
	$a0
}

        
