rule Win_Spyware_Banker_2922
{
strings:
	$a0 = { 753330dd84af07fedf5042a56357b6ff5af88f6cdb14c99658d8f292fa0e5786b773a9a6173b5fbc85fe2a56219fe2420f6cc1a3797f5b53ccf0f75c66f090df0c51454430f8fc7244ecab6f601d4d5ab4fc31e79858a200722370d2876526c4227b5a5027f2f8505505ded38308 }

condition:
	$a0
}

        