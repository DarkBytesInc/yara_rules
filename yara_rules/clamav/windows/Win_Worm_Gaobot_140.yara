rule Win_Worm_Gaobot_140
{
strings:
	$a0 = { efb0be321aebb10eebbf03eb7dddac0f8bca3a4c79fd9fb2beb47bd6df31acaf8f71585fe1629de723c1fa79c3dc8b178f0e895cbc38f70eeb50f8a44974a9896ddee76fe7713d731612f7c23858a23594765578bbb979d5aebe9c6d5943d19f82d6a70eb57eb6b979 }

condition:
	$a0
}

        
