rule Win_Trojan_FakeAV_112
{
strings:
	$a0 = { 558beceb0b010000010000000001000081c424ffffff83f364e8b5ffffff52ffb508ffffff6a57e871ffffff23fe518d4de45152e8d4feffff2bd88d9534ffffff528d45fc5052e84ffeffffe80afeffffe8edfdffffe89ffdffff6a0068a336b288e812fdffff0bc00f8418000000b9a0860100eb08500bc97502c9c3490bc0 }

condition:
	$a0
}

        
