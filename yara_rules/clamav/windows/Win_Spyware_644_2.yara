rule Win_Spyware_644_2
{
strings:
	$a0 = { e3ac622aecd65d9e8c7e9b88b9d3b5b5f9e638f6035d3c4417cf024458bace3846ac17b9101f63eb9dba36dbc4671299de870dafd66acd7ed20c137f1f0a61b419ce4bc04bc59be2ebb1cf0ef84b305aef7706ef69b100ad15bed304481b487ad92e83ff6723e25cd1609833f3e7 }

condition:
	$a0
}

        
